"""Interface de linha de comando.

    sentinela analisar /var/log/auth.log /var/log/nginx/access.log --html relatorio.html
    sentinela monitorar /var/log/auth.log
    sentinela demo
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .detectors import Config, analyze, rank_attackers
from .mitre import technique_name
from .models import Alert, Event, Severity
from .parsers import FileStats, parse_files, parse_line
from .report import to_html, to_json
from .sample import generate

# --------------------------------------------------------------------------- #
# cores no terminal
# --------------------------------------------------------------------------- #

_COLOR = {
    Severity.CRITICA: "\033[1;97;41m",
    Severity.ALTA: "\033[1;38;5;208m",
    Severity.MEDIA: "\033[1;33m",
    Severity.BAIXA: "\033[1;36m",
}
_RESET, _DIM, _BOLD, _GREEN = "\033[0m", "\033[2m", "\033[1m", "\033[1;32m"


class _Out:
    def __init__(self, color: bool):
        self.color = color

    def c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text

    def sev(self, s: Severity) -> str:
        return self.c(_COLOR[s], f" {s.label:<7} ")


def _use_color(flag_off: bool) -> bool:
    return not flag_off and sys.stdout.isatty() and "NO_COLOR" not in os.environ


BANNER = r"""
   ____             _   _            _
  / ___|  ___ _ __ | |_(_)_ __   ___| | __ _
  \___ \ / _ \ '_ \| __| | '_ \ / _ \ |/ _` |
   ___) |  __/ | | | |_| | | | |  __/ | (_| |
  |____/ \___|_| |_|\__|_|_| |_|\___|_|\__,_|
"""


# Caracteres de controle C0 (exceto nenhum), DEL e C1 (inclui CSI \x9b).
_CONTROL = {c: f"\\x{c:02x}" for c in [*range(0x20), 0x7F, *range(0x80, 0xA0)]}


def safe(text: str) -> str:
    """Neutraliza caracteres de controle vindos dos logs antes de imprimir.

    O conteúdo dos logs é controlado pelo atacante (ex.: nome de usuário SSH).
    Sem isso, sequências ANSI/OSC poderiam limpar a tela, alterar o título da
    janela ou esconder alertas no terminal do analista.
    """
    return text.translate(_CONTROL)


def _print_alert(o: _Out, a: Alert) -> None:
    print(f"{o.sev(a.severity)} {o.c(_DIM, a.rule_id)} {o.c(_BOLD, a.title)} "
          f"— {o.c(_GREEN, safe(a.ip))} {o.c(_DIM, f'({a.count} evento(s), {a.first_seen:%d/%m %H:%M})')}")
    print(f"          {safe(a.description)}")
    for n in a.notes:
        print(f"          {o.c(_COLOR[Severity.MEDIA], '⚠ ' + safe(n))}")
    mitre = ", ".join(f"{t} {technique_name(t)}" for t in a.mitre)
    print(f"          {o.c(_DIM, 'MITRE ATT&CK: ' + mitre)}\n")


def _print_summary(o: _Out, events: Sequence[Event], alerts: Sequence[Alert],
                   stats: Sequence[FileStats]) -> None:
    print(o.c(_GREEN, BANNER))
    print(o.c(_DIM, f"  v{__version__} · detector de ataques em logs SSH e web\n"))
    for s in stats:
        print(f"  📄 {safe(s.path)}: {s.lines} linhas, {s.parsed} eventos relevantes")
    if events:
        print(f"  🕒 período: {events[0].timestamp:%d/%m/%Y %H:%M} → {events[-1].timestamp:%d/%m/%Y %H:%M}")
    print()

    if not alerts:
        print(o.c(_GREEN, "  ✔ Nenhum alerta. Tudo tranquilo.\n"))
        return
    for a in alerts:
        _print_alert(o, a)

    print(o.c(_BOLD, "  TOP ATACANTES"))
    for att in rank_attackers(alerts)[:10]:
        print(f"  {o.sev(att.max_severity)} {safe(att.ip):<18} risco {att.score:>3}  "
              f"{o.c(_DIM, ','.join(att.sources) + '  ' + ' '.join(att.rules))}")
    counts = {s: sum(1 for a in alerts if a.severity == s) for s in Severity}
    resumo = " · ".join(f"{s.label}: {counts[s]}" for s in sorted(Severity, reverse=True))
    print(f"\n  {o.c(_BOLD, f'{len(alerts)} alertas')}  ({resumo})\n")


def _config(args: argparse.Namespace) -> Config:
    return Config(
        brute_threshold=args.limiar_forca_bruta,
        brute_window=args.janela_forca_bruta,
        dirscan_threshold=args.limiar_varredura,
    )


def _write_outputs(args, events, alerts, stats) -> None:
    if args.json:
        Path(args.json).write_text(to_json(events, alerts, stats), encoding="utf-8")
        print(f"  💾 JSON salvo em {args.json}")
    if args.html:
        Path(args.html).write_text(to_html(events, alerts, stats), encoding="utf-8")
        print(f"  📊 Dashboard HTML salvo em {args.html}")


# --------------------------------------------------------------------------- #
# comandos
# --------------------------------------------------------------------------- #

def cmd_analisar(args: argparse.Namespace) -> int:
    o = _Out(_use_color(args.sem_cor))
    missing = [p for p in args.arquivos if not Path(p).is_file()]
    if missing:
        print(f"erro: arquivo não encontrado: {', '.join(missing)}", file=sys.stderr)
        return 2

    events, stats = parse_files(args.arquivos, year=args.ano)
    alerts = analyze(events, _config(args))
    min_sev = Severity.parse(args.severidade_minima)
    alerts = [a for a in alerts if a.severity >= min_sev]

    _print_summary(o, events, alerts, stats)
    _write_outputs(args, events, alerts, stats)

    if args.falhar_em:
        limit = Severity.parse(args.falhar_em)
        if any(a.severity >= limit for a in alerts):
            return 1
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    folder = Path(args.pasta)
    auth, web = generate(folder)
    print(f"  Logs de demonstração gerados em {folder}/")
    args.arquivos = [str(auth), str(web)]
    args.html = args.html or str(folder / "relatorio.html")
    args.json = args.json or str(folder / "relatorio.json")
    args.falhar_em = None
    args.ano = args.ano or (datetime.now() - timedelta(days=1)).year  # logs são de "ontem"
    return cmd_analisar(args)


def cmd_monitorar(args: argparse.Namespace) -> int:
    """Acompanha os arquivos como `tail -f` e emite alertas novos em tempo real."""
    o = _Out(_use_color(args.sem_cor))
    if hasattr(sys.stdout, "reconfigure"):  # alertas saem na hora mesmo com | tee ou > arquivo
        sys.stdout.reconfigure(line_buffering=True)
    cfg = _config(args)
    year = args.ano or time.localtime().tm_year
    handles = []
    for p in args.arquivos:
        fh = open(p, "r", encoding="utf-8", errors="replace")
        if not args.desde_inicio:
            fh.seek(0, os.SEEK_END)
        handles.append((Path(p).name, fh))

    events: deque = deque(maxlen=200_000)
    reported: dict = {}
    print(o.c(_GREEN, BANNER))
    print(f"  👁  Monitorando {', '.join(n for n, _ in handles)} — Ctrl+C para sair\n")
    try:
        while True:
            new = 0
            for name, fh in handles:
                for line in fh.readlines():
                    ev = parse_line(line, year, file=name)
                    if ev:
                        events.append(ev)
                        new += 1
            if new:
                ordered = sorted(events, key=lambda e: e.timestamp)
                for a in analyze(ordered, cfg):
                    key = (a.rule_id, a.ip)
                    if a.severity < Severity.parse(args.severidade_minima):
                        continue
                    if key not in reported or a.severity > reported[key]:
                        reported[key] = a.severity
                        print(o.c(_DIM, time.strftime("  [%H:%M:%S] novo alerta")))
                        _print_alert(o, a)
            time.sleep(args.intervalo)
    except KeyboardInterrupt:
        print(f"\n  Encerrado. {len(reported)} alerta(s) emitido(s).")
    finally:
        for _, fh in handles:
            fh.close()
    return 0


# --------------------------------------------------------------------------- #
# argparse
# --------------------------------------------------------------------------- #

def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--ano", type=int, help="ano dos logs syslog (que não trazem o ano). Padrão: ano atual")
    p.add_argument("--severidade-minima", default="baixa",
                   choices=["baixa", "media", "alta", "critica"], help="esconde alertas abaixo deste nível")
    p.add_argument("--limiar-forca-bruta", type=int, default=Config.brute_threshold, metavar="N",
                   help=f"falhas SSH na janela para alertar (padrão {Config.brute_threshold})")
    p.add_argument("--janela-forca-bruta", type=int, default=Config.brute_window, metavar="SEG",
                   help=f"tamanho da janela em segundos (padrão {Config.brute_window})")
    p.add_argument("--limiar-varredura", type=int, default=Config.dirscan_threshold, metavar="N",
                   help=f"respostas 404 por minuto para alertar varredura (padrão {Config.dirscan_threshold})")
    p.add_argument("--sem-cor", action="store_true", help="desativa cores no terminal")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinela",
        description="Detecta ataques em logs de SSH e servidores web (Apache/Nginx) "
                    "e mapeia cada achado para o MITRE ATT&CK.",
    )
    parser.add_argument("--version", action="version", version=f"sentinela {__version__}")
    sub = parser.add_subparsers(dest="comando", required=True)

    p = sub.add_parser("analisar", help="analisa um ou mais arquivos de log")
    p.add_argument("arquivos", nargs="+", help="auth.log, access.log, arquivos .gz...")
    p.add_argument("--html", metavar="ARQ", help="gera dashboard HTML")
    p.add_argument("--json", metavar="ARQ", help="gera relatório JSON (para SIEM/automação)")
    p.add_argument("--falhar-em", choices=["baixa", "media", "alta", "critica"],
                   help="sai com código 1 se houver alerta neste nível ou acima (útil em CI/cron)")
    _common(p)
    p.set_defaults(func=cmd_analisar)

    p = sub.add_parser("monitorar", help="acompanha logs em tempo real (tail -f)")
    p.add_argument("arquivos", nargs="+")
    p.add_argument("--intervalo", type=float, default=2.0, help="segundos entre leituras (padrão 2)")
    p.add_argument("--desde-inicio", action="store_true", help="processa o arquivo inteiro antes de seguir")
    _common(p)
    p.set_defaults(func=cmd_monitorar)

    p = sub.add_parser("demo", help="gera logs com um cenário de ataque e analisa")
    p.add_argument("--pasta", default="sentinela-demo", help="onde salvar logs e relatórios")
    p.add_argument("--html", metavar="ARQ")
    p.add_argument("--json", metavar="ARQ")
    _common(p)
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
