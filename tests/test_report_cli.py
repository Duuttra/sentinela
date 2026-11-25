import json
from datetime import datetime

from sentinela.cli import main
from sentinela.detectors import analyze
from sentinela.models import Event
from sentinela.parsers import FileStats
from sentinela.report import to_html, to_json

PAYLOAD = "<script>alert('pwned')</script>"


def _xss_events():
    return [Event(datetime(2026, 11, 24, 10, 0, i), "web", "192.0.2.1", "request",
                  method="GET", path="/busca?q=" + PAYLOAD, status=200,
                  user_agent='"><img src=x onerror=alert(1)>',
                  raw=f'192.0.2.1 "GET /busca?q={PAYLOAD}" 200') for i in range(3)]


def test_html_report_escapes_log_content():
    """Os logs trazem payloads XSS: o relatório não pode executá-los."""
    events = _xss_events()
    html = to_html(events, analyze(events), [FileStats("access.log", 3, 3)])
    assert PAYLOAD not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    # o único <script> do documento é o do próprio filtro do dashboard
    assert html.count("<script>") == 1


def test_json_report_is_valid():
    events = _xss_events()
    data = json.loads(to_json(events, analyze(events), [FileStats("access.log", 3, 3)]))
    assert data["resumo"]["eventos"] == 3
    assert data["alertas"][0]["mitre_attack"][0]["url"].startswith("https://attack.mitre.org/")
    assert data["atacantes"][0]["ip"] == "192.0.2.1"


def test_html_with_no_events():
    html = to_html([], [], [])
    assert "Nenhum alerta" in html


def test_cli_demo_end_to_end(tmp_path, capsys):
    assert main(["demo", "--pasta", str(tmp_path), "--sem-cor"]) == 0
    out = capsys.readouterr().out
    assert "SSH-003" in out and "WEB-005" in out
    data = json.loads((tmp_path / "relatorio.json").read_text(encoding="utf-8"))
    found = {a["regra"] for a in data["alertas"]}
    expected = {"SSH-001", "SSH-002", "SSH-003", "SSH-004", "WEB-001", "WEB-002", "WEB-003",
                "WEB-004", "WEB-005", "WEB-006", "WEB-007", "WEB-010", "WEB-011"}
    assert expected <= found
    # nenhum visitante legítimo (rede 10.20.x.x) foi acusado
    assert not any(a["ip"].startswith("10.20.") for a in data["alertas"])
    assert (tmp_path / "relatorio.html").stat().st_size > 10_000


def test_cli_fail_on_exit_code(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(
        f"Nov 24 03:00:{i:02d} s sshd[1]: Failed password for root from 203.0.113.9 port 1 ssh2\n"
        for i in range(12)
    ))
    base = ["analisar", str(log), "--ano", "2026", "--sem-cor"]
    assert main(base) == 0
    assert main(base + ["--falhar-em", "alta"]) == 1
    assert main(base + ["--falhar-em", "critica"]) == 0


def test_cli_missing_file(tmp_path):
    assert main(["analisar", str(tmp_path / "nao-existe.log")]) == 2
