"""Parsers de log: OpenSSH (auth.log / journald) e Apache/Nginx (combined).

O formato é detectado linha a linha, então dá para passar arquivos
misturados. Arquivos .gz (rotacionados pelo logrotate) também são lidos.
"""

from __future__ import annotations

import gzip
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .models import Event

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

_IP = r"[0-9A-Fa-f:.]+"

# "Nov 24 03:12:01 srv sshd[812]: ..."  (syslog clássico, sem ano)
_SSH_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$"
)
# "2026-11-24T03:12:01.123456-03:00 srv sshd[812]: ..."  (rsyslog/journald ISO)
_SSH_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$"
)
_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>" + _IP + r") port \d+"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
    r"(?P<user>\S+) from (?P<ip>" + _IP + r") port \d+"
)

# Apache/Nginx "combined": aspas dentro dos campos vêm escapadas como \"
_Q = r'(?:[^"\\]|\\.)*'
_WEB = re.compile(
    r"^(?P<ip>" + _IP + r") \S+ \S+ \[(?P<ts>[^\]]+)\] "
    r'"(?P<req>' + _Q + r')" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>' + _Q + r')" "(?P<ua>' + _Q + r')")?'
)
_WEB_TS = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})"
)


@dataclass
class FileStats:
    path: str
    lines: int = 0
    parsed: int = 0

    @property
    def ignored(self) -> int:
        return self.lines - self.parsed


def parse_line(line: str, year: int, file: str = "", line_no: int = 0) -> Optional[Event]:
    """Converte uma linha em Event, ou None se ela não for relevante."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    event = _parse_ssh(line, year) or _parse_web(line)
    if event is not None:
        event.raw = line
        event.file = file
        event.line_no = line_no
    return event


def _parse_ssh(line: str, year: int) -> Optional[Event]:
    m = _SSH_SYSLOG.match(line)
    if m:
        month = MONTHS.get(m["mon"])
        if month is None:
            return None
        h, mi, s = (int(x) for x in m["time"].split(":"))
        try:
            ts = datetime(year, month, int(m["day"]), h, mi, s)
        except ValueError:
            return None
    else:
        m = _SSH_ISO.match(line)
        if not m:
            return None
        ts = datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%S")
    msg = m["msg"]

    f = _SSH_FAILED.search(msg)
    if f:
        return Event(ts, "ssh", f["ip"], "failed",
                     user=f["user"], invalid_user=bool(f["invalid"]))
    a = _SSH_ACCEPTED.search(msg)
    if a:
        return Event(ts, "ssh", a["ip"], "accepted", user=a["user"])
    return None


def _parse_web(line: str) -> Optional[Event]:
    m = _WEB.match(line)
    if not m:
        return None
    t = _WEB_TS.match(m["ts"])
    if not t:
        return None
    month = MONTHS.get(t["mon"].capitalize())
    if month is None:
        return None
    try:
        ts = datetime(int(t["year"]), month, int(t["day"]),
                      int(t["h"]), int(t["m"]), int(t["s"]))
    except ValueError:
        return None

    req = m["req"].replace('\\"', '"')
    parts = req.split(" ")
    if len(parts) >= 3 and parts[-1].startswith("HTTP/"):
        method, path = parts[0], " ".join(parts[1:-1])
    elif len(parts) == 2:
        method, path = parts
    else:  # requisição malformada (ex.: handshake TLS na porta 80)
        method, path = None, req

    ua = (m["ua"] or "").replace('\\"', '"')
    return Event(ts, "web", m["ip"], "request", method=method, path=path,
                 status=int(m["status"]), user_agent="" if ua == "-" else ua)


def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def parse_files(paths: Iterable[str], year: Optional[int] = None) -> Tuple[List[Event], List[FileStats]]:
    """Lê todos os arquivos e devolve os eventos em ordem cronológica."""
    year = year or datetime.now().year
    events: List[Event] = []
    stats: List[FileStats] = []
    for p in paths:
        path = Path(p)
        st = FileStats(str(path))
        with _open(path) as fh:
            for n, line in enumerate(fh, start=1):
                st.lines += 1
                ev = parse_line(line, year, file=path.name, line_no=n)
                if ev is not None:
                    st.parsed += 1
                    events.append(ev)
        stats.append(st)
    events.sort(key=lambda e: e.timestamp)  # sort estável: mantém a ordem do arquivo
    return events, stats
