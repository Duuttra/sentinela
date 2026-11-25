"""Estruturas de dados centrais: eventos de log e alertas."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import List, Optional

from .mitre import technique_name, technique_url


class Severity(IntEnum):
    BAIXA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4

    @property
    def label(self) -> str:
        return _LABELS[self]

    @classmethod
    def parse(cls, text: str) -> "Severity":
        norm = text.strip().upper().replace("É", "E").replace("Í", "I")
        try:
            return cls[norm]
        except KeyError:
            raise ValueError(f"severidade inválida: {text!r}") from None

    def escalate(self) -> "Severity":
        return Severity(min(self + 1, Severity.CRITICA))


_LABELS = {
    Severity.BAIXA: "BAIXA",
    Severity.MEDIA: "MÉDIA",
    Severity.ALTA: "ALTA",
    Severity.CRITICA: "CRÍTICA",
}


@dataclass(eq=False)
class Event:
    """Uma linha de log normalizada."""

    timestamp: datetime
    source: str  # "ssh" ou "web"
    ip: str
    action: str  # ssh: "failed" | "accepted"; web: "request"
    user: Optional[str] = None
    invalid_user: bool = False
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None
    raw: str = ""
    file: str = ""
    line_no: int = 0


@dataclass(eq=False)
class Alert:
    """Uma detecção: regra disparada por um IP, com as linhas que a provam."""

    rule_id: str
    title: str
    severity: Severity
    ip: str
    description: str
    mitre: List[str]
    events: List[Event] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def first_seen(self) -> datetime:
        return min(e.timestamp for e in self.events)

    @property
    def last_seen(self) -> datetime:
        return max(e.timestamp for e in self.events)

    @property
    def count(self) -> int:
        return len(self.events)

    def evidence(self, limit: int = 6) -> List[str]:
        evs = self.events
        if len(evs) <= limit:
            return [e.raw for e in evs]
        head = limit - 1
        return [e.raw for e in evs[:head]] + [
            f"... (+{len(evs) - limit} linhas) ...",
            evs[-1].raw,
        ]

    def to_dict(self) -> dict:
        return {
            "regra": self.rule_id,
            "titulo": self.title,
            "severidade": self.severity.label,
            "ip": self.ip,
            "descricao": self.description,
            "observacoes": self.notes,
            "eventos": self.count,
            "primeira_ocorrencia": self.first_seen.isoformat(),
            "ultima_ocorrencia": self.last_seen.isoformat(),
            "mitre_attack": [
                {"id": t, "nome": technique_name(t), "url": technique_url(t)}
                for t in self.mitre
            ],
            "evidencias": [
                {"arquivo": e.file, "linha": e.line_no, "log": e.raw}
                for e in self.events[:20]
            ],
        }
