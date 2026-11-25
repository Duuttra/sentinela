"""Regras de detecção.

Dois tipos de regra:
  * comportamentais — contam eventos por IP numa janela deslizante
    (força bruta, varredura de diretórios, login após falhas);
  * por assinatura — procuram padrões de ataque na URL/User-Agent
    (SQLi, XSS, path traversal, injeção de comando, Log4Shell...).

Cada alerta é agrupado por (regra, IP) e carrega as linhas de log
que o originaram, para o analista conferir.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple
from urllib.parse import unquote_plus

from .models import Alert, Event, Severity


@dataclass
class Config:
    brute_threshold: int = 10          # falhas SSH ...
    brute_window: int = 300            # ... dentro de N segundos
    spray_users: int = 5               # usuários distintos testados pelo mesmo IP
    compromise_min_failures: int = 3   # falhas antes de um login aceito
    compromise_lookback: int = 3600    # ... na última hora
    dirscan_threshold: int = 20        # respostas 404 ...
    dirscan_window: int = 60           # ... dentro de N segundos
    web_login_threshold: int = 10      # POSTs em páginas de login ...
    web_login_window: int = 300        # ... dentro de N segundos


# --------------------------------------------------------------------------- #
# utilidades
# --------------------------------------------------------------------------- #

def _by_ip(events: Iterable[Event]) -> Dict[str, List[Event]]:
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        groups[e.ip].append(e)
    return groups


def max_in_window(events: Sequence[Event], window_s: int) -> int:
    """Maior número de eventos dentro de qualquer janela de `window_s` segundos.

    `events` precisa estar em ordem cronológica. Two pointers: O(n).
    """
    best = start = 0
    for end in range(len(events)):
        while (events[end].timestamp - events[start].timestamp).total_seconds() > window_s:
            start += 1
        best = max(best, end - start + 1)
    return best


def _top(counter: Counter, n: int = 3) -> str:
    return ", ".join(f"{k or '(vazio)'} ({v}x)" for k, v in counter.most_common(n))


def _decode(text: str) -> str:
    """Decodifica URL-encoding até duas vezes (atacantes usam double encoding)."""
    out = text
    for _ in range(2):
        new = unquote_plus(out)
        if new == out:
            break
        out = new
    return out


def _window_label(seconds: int) -> str:
    return f"{seconds // 60} min" if seconds >= 60 and seconds % 60 == 0 else f"{seconds} s"


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #

def detect_ssh(events: Sequence[Event], cfg: Config) -> List[Alert]:
    alerts: List[Alert] = []
    ssh = [e for e in events if e.source == "ssh"]
    failed_by_ip = _by_ip(e for e in ssh if e.action == "failed")

    for ip, evs in failed_by_ip.items():
        peak = max_in_window(evs, cfg.brute_window)
        if peak >= cfg.brute_threshold:
            alerts.append(Alert(
                "SSH-001", "Força bruta contra o SSH", Severity.ALTA, ip,
                f"{len(evs)} falhas de autenticação, com pico de {peak} em "
                f"{_window_label(cfg.brute_window)}. Usuários mais tentados: "
                f"{_top(Counter(e.user for e in evs))}.",
                ["T1110.001"], evs,
            ))

        users = {e.user for e in evs}
        if len(users) >= cfg.spray_users:
            invalid = sum(1 for e in evs if e.invalid_user)
            alerts.append(Alert(
                "SSH-002", "Password spraying / enumeração de usuários", Severity.ALTA, ip,
                f"{len(users)} usuários diferentes testados a partir do mesmo IP; "
                f"{invalid} tentativa(s) com usuários que não existem no servidor.",
                ["T1110.003", "T1087"], evs,
            ))

    seen = set()
    for acc in (e for e in ssh if e.action == "accepted"):
        prior = [
            f for f in failed_by_ip.get(acc.ip, [])
            if 0 <= (acc.timestamp - f.timestamp).total_seconds() <= cfg.compromise_lookback
        ]
        key = (acc.ip, acc.user)
        if len(prior) >= cfg.compromise_min_failures and key not in seen:
            seen.add(key)
            alerts.append(Alert(
                "SSH-003", "Login SSH bem-sucedido após várias falhas", Severity.CRITICA, acc.ip,
                f"O usuário '{acc.user}' autenticou com sucesso em "
                f"{acc.timestamp:%d/%m %H:%M:%S} depois de {len(prior)} falhas vindas "
                f"do mesmo IP. Forte indício de credencial comprometida.",
                ["T1110", "T1078"], prior + [acc],
                notes=["Resposta sugerida: bloquear o IP, encerrar sessões ativas do usuário, "
                       "trocar a senha e revisar o histórico de comandos (~/.bash_history)."],
            ))

        if acc.user == "root":
            alerts.append(Alert(
                "SSH-004", "Login direto como root", Severity.MEDIA, acc.ip,
                f"Login de root aceito em {acc.timestamp:%d/%m %H:%M:%S}. "
                "Acesso direto como root dificulta auditoria e amplia o impacto "
                "de uma senha vazada.",
                ["T1078.003"], [acc],
                notes=["Recomendação: 'PermitRootLogin no' no sshd_config e uso de sudo."],
            ))
    return alerts


# --------------------------------------------------------------------------- #
# Web — assinaturas
# --------------------------------------------------------------------------- #

@dataclass
class Signature:
    rule_id: str
    title: str
    severity: Severity
    patterns: List[str]
    mitre: List[str]
    target: str = "request"     # "request" (URL + UA), "path" ou "ua"
    escalate_on_2xx: bool = True

    def __post_init__(self) -> None:
        self.regex = re.compile("|".join(f"(?:{p})" for p in self.patterns), re.IGNORECASE)


SIGNATURES: List[Signature] = [
    Signature(
        "WEB-001", "SQL Injection", Severity.ALTA,
        [
            r"\bunion\b[\s/*()]+(?:all[\s/*()]+)?select\b",
            r"['\"]\s*(?:or|and)\s+['\"]?\w+['\"]?\s*(?:=|like)\s*['\"]?\w+",
            r"\b(?:or|and)\s+\d+\s*=\s*\d+",
            r"\b(?:sleep|benchmark|pg_sleep)\s*\(",
            r"\bwaitfor\s+delay\b",
            r"\binformation_schema\b",
            r"\b(?:extractvalue|updatexml|load_file)\s*\(",
            r"['\"]\s*(?:--|#|/\*)",
        ],
        ["T1190"],
    ),
    Signature(
        "WEB-002", "Cross-Site Scripting (XSS)", Severity.MEDIA,
        [
            r"<\s*/?\s*script\b",
            r"javascript\s*:",
            r"\bon(?:error|load|mouseover|focus|click|toggle)\s*=",
            r"<\s*(?:svg|img|iframe|body)\b[^>]*>",
            r"document\.(?:cookie|domain)",
        ],
        ["T1190", "T1059.007"],
    ),
    Signature(
        "WEB-003", "Path traversal / Local File Inclusion", Severity.ALTA,
        [
            r"\.\./|\.\.\\",
            r"/etc/(?:passwd|shadow|hosts)\b",
            r"\b(?:win|boot)\.ini\b",
            r"\b(?:php|file|expect|data)://",
            r"/proc/self/",
        ],
        ["T1190", "T1083"],
        target="path",
    ),
    Signature(
        "WEB-004", "Injeção de comandos no sistema operacional", Severity.CRITICA,
        [r"(?:;|\||&&|`|\$\()\s*(?:cat|id|whoami|uname|wget|curl|nc|ncat|bash|sh|ping|nslookup)\b"],
        ["T1190", "T1059.004"],
        target="path",
    ),
    Signature(
        "WEB-005", "Exploração do Log4Shell (CVE-2021-44228)", Severity.CRITICA,
        [r"\$\{\s*(?:jndi|lower:|upper:|::-|env:)"],
        ["T1190"],
    ),
    Signature(
        "WEB-006", "Acesso a arquivos sensíveis", Severity.MEDIA,
        [
            r"/\.env\b",
            r"/\.(?:git|svn|aws|ssh)/",
            r"/\.ht(?:passwd|access)\b",
            r"/id_rsa\b",
            r"/wp-config\.php",
            r"/web\.config\b",
            r"/(?:backup|dump|db|database|site)\.(?:sql|zip|tar\.gz|tgz|bak)\b",
        ],
        ["T1552.001"],
        target="path",
    ),
    Signature(
        "WEB-007", "Ferramenta de scanner/ataque identificada", Severity.BAIXA,
        [r"sqlmap|nikto|nmap|masscan|nuclei|gobuster|dirbuster|ffuf|wfuzz|"
         r"acunetix|nessus|openvas|zgrab|hydra|wpscan|feroxbuster"],
        ["T1595.002"],
        target="ua",
        escalate_on_2xx=False,
    ),
]


def _target_text(e: Event, target: str) -> str:
    path = _decode(e.path or "")
    ua = e.user_agent or ""
    if target == "path":
        return path
    if target == "ua":
        return ua
    return path + "\n" + ua


def detect_web_signatures(events: Sequence[Event]) -> List[Alert]:
    web = [e for e in events if e.source == "web"]
    hits: Dict[Tuple[str, str], List[Event]] = defaultdict(list)
    for e in web:
        for sig in SIGNATURES:
            if sig.regex.search(_target_text(e, sig.target)):
                hits[(sig.rule_id, e.ip)].append(e)

    by_id = {s.rule_id: s for s in SIGNATURES}
    alerts: List[Alert] = []
    for (rule_id, ip), evs in hits.items():
        sig = by_id[rule_id]
        severity = sig.severity
        notes: List[str] = []
        ok = [e for e in evs if e.status is not None and 200 <= e.status < 300]
        if sig.escalate_on_2xx and ok:
            severity = severity.escalate()
            notes.append(
                f"{len(ok)} requisição(ões) maliciosa(s) receberam resposta 2xx — "
                "o ataque pode ter funcionado. Severidade elevada."
            )
        if rule_id == "WEB-007":
            tools = Counter(
                m.group(0).lower() for e in evs
                if (m := sig.regex.search(e.user_agent or ""))
            )
            desc = f"{len(evs)} requisições com User-Agent de ferramenta ofensiva: {_top(tools)}."
        else:
            statuses = Counter(e.status for e in evs)
            desc = (f"{len(evs)} requisição(ões) com padrão de {sig.title}. "
                    f"Códigos de resposta: {_top(statuses, 5)}.")
        alerts.append(Alert(rule_id, sig.title, severity, ip, desc, sig.mitre, evs, notes))
    return alerts


# --------------------------------------------------------------------------- #
# Web — comportamento
# --------------------------------------------------------------------------- #

_LOGIN_PATH = re.compile(r"login|signin|sign-in|wp-login|/auth|/session", re.IGNORECASE)


def detect_web_behavior(events: Sequence[Event], cfg: Config) -> List[Alert]:
    web = [e for e in events if e.source == "web"]
    alerts: List[Alert] = []

    for ip, evs in _by_ip(e for e in web if e.status == 404).items():
        peak = max_in_window(evs, cfg.dirscan_window)
        if peak >= cfg.dirscan_threshold:
            alerts.append(Alert(
                "WEB-010", "Varredura de diretórios (wordlist)", Severity.MEDIA, ip,
                f"{len(evs)} respostas 404, com pico de {peak} em "
                f"{_window_label(cfg.dirscan_window)}. Típico de gobuster/dirb/ffuf.",
                ["T1595.003"], evs,
            ))

    logins = (e for e in web if e.method == "POST" and _LOGIN_PATH.search(e.path or ""))
    for ip, evs in _by_ip(logins).items():
        peak = max_in_window(evs, cfg.web_login_window)
        if peak >= cfg.web_login_threshold:
            fails = sum(1 for e in evs if e.status in (401, 403))
            alerts.append(Alert(
                "WEB-011", "Força bruta em formulário de login", Severity.ALTA, ip,
                f"{len(evs)} tentativas de login ({fails} recusadas com 401/403), pico de "
                f"{peak} em {_window_label(cfg.web_login_window)}.",
                ["T1110"], evs,
            ))
    return alerts


# --------------------------------------------------------------------------- #
# orquestração
# --------------------------------------------------------------------------- #

def analyze(events: Sequence[Event], cfg: Config = None) -> List[Alert]:
    cfg = cfg or Config()
    alerts = (
        detect_ssh(events, cfg)
        + detect_web_signatures(events)
        + detect_web_behavior(events, cfg)
    )
    alerts.sort(key=lambda a: (-a.severity, a.first_seen, a.rule_id))
    return alerts


_WEIGHT = {Severity.BAIXA: 1, Severity.MEDIA: 3, Severity.ALTA: 7, Severity.CRITICA: 15}


@dataclass
class Attacker:
    ip: str
    score: int
    max_severity: Severity
    rules: List[str]
    sources: List[str]
    events: int


def rank_attackers(alerts: Sequence[Alert]) -> List[Attacker]:
    """Pontua cada IP somando o peso das regras disparadas (correlação SSH + web)."""
    groups: Dict[str, List[Alert]] = defaultdict(list)
    for a in alerts:
        groups[a.ip].append(a)
    ranking = []
    for ip, alist in groups.items():
        ranking.append(Attacker(
            ip=ip,
            score=sum(_WEIGHT[a.severity] for a in alist),
            max_severity=max(a.severity for a in alist),
            rules=sorted({a.rule_id for a in alist}),
            sources=sorted({e.source for a in alist for e in a.events}),
            events=len({id(e) for a in alist for e in a.events}),
        ))
    ranking.sort(key=lambda x: (-x.score, -x.max_severity, x.ip))
    return ranking
