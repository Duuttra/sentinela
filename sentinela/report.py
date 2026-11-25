"""Saídas: JSON (para SIEM/automação) e dashboard HTML autocontido.

Todo conteúdo vindo dos logs passa por html.escape — logs de ataque
contêm payloads XSS, e um relatório que os renderizasse viraria vítima.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from html import escape
from typing import List, Sequence

from . import __version__
from .detectors import rank_attackers
from .mitre import technique_name, technique_url
from .models import Alert, Event, Severity
from .parsers import FileStats

SEV_CLASS = {
    Severity.BAIXA: "low",
    Severity.MEDIA: "med",
    Severity.ALTA: "high",
    Severity.CRITICA: "crit",
}


def _period(events: Sequence[Event]):
    if not events:
        return None, None
    return events[0].timestamp, events[-1].timestamp


def to_json(events: Sequence[Event], alerts: Sequence[Alert], stats: Sequence[FileStats]) -> str:
    start, end = _period(events)
    data = {
        "ferramenta": f"sentinela {__version__}",
        "gerado_em": datetime.now().isoformat(timespec="seconds"),
        "periodo": {
            "inicio": start.isoformat() if start else None,
            "fim": end.isoformat() if end else None,
        },
        "arquivos": [
            {"arquivo": s.path, "linhas": s.lines, "eventos": s.parsed, "ignoradas": s.ignored}
            for s in stats
        ],
        "resumo": {
            "eventos": len(events),
            "alertas": len(alerts),
            "por_severidade": {
                sev.label: sum(1 for a in alerts if a.severity == sev)
                for sev in sorted(Severity, reverse=True)
            },
        },
        "atacantes": [
            {"ip": a.ip, "pontuacao": a.score, "severidade_maxima": a.max_severity.label,
             "regras": a.rules, "fontes": a.sources, "eventos": a.events}
            for a in rank_attackers(alerts)
        ],
        "alertas": [a.to_dict() for a in alerts],
    }
    return json.dumps(data, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_BUCKETS = [60, 300, 900, 1800, 3600, 3 * 3600, 6 * 3600, 86400]


def _timeline_svg(events: Sequence[Event], alerts: Sequence[Alert]) -> str:
    if not events:
        return '<p class="muted">Sem eventos.</p>'
    start, end = _period(events)
    span = max((end - start).total_seconds(), 1)
    size = next((b for b in _BUCKETS if span / b <= 48), _BUCKETS[-1])
    midnight = start.replace(hour=0, minute=0, second=0, microsecond=0)
    offset = (start - midnight).total_seconds() // size * size
    origin = midnight + timedelta(seconds=offset)
    n = int((end - origin).total_seconds() // size) + 1

    bad_ids = {id(e) for a in alerts for e in a.events}
    normal, bad = [0] * n, [0] * n
    for e in events:
        i = int((e.timestamp - origin).total_seconds() // size)
        (bad if id(e) in bad_ids else normal)[i] += 1

    W, H, PAD_L, PAD_B, PAD_T = 960, 220, 44, 28, 10
    plot_w, plot_h = W - PAD_L - 8, H - PAD_B - PAD_T
    peak = max(a + b for a, b in zip(normal, bad)) or 1
    bw = plot_w / n
    parts = [f'<svg viewBox="0 0 {W} {H}" class="timeline" role="img" '
             f'aria-label="Linha do tempo de eventos">']
    for frac in (0, 0.5, 1):
        y = PAD_T + plot_h * (1 - frac)
        parts.append(f'<line x1="{PAD_L}" x2="{W - 8}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>'
                     f'<text x="{PAD_L - 6}" y="{y + 4:.1f}" class="axis" text-anchor="end">'
                     f'{round(peak * frac)}</text>')
    label_every = max(1, n // 8)
    for i in range(n):
        x = PAD_L + i * bw + 1
        w = max(bw - 2, 1)
        hn = plot_h * normal[i] / peak
        hb = plot_h * bad[i] / peak
        t = origin + timedelta(seconds=i * size)
        tip = f"{t:%d/%m %H:%M} — {normal[i]} normais, {bad[i]} suspeitos"
        y_n = PAD_T + plot_h - hn
        parts.append(f'<g><title>{tip}</title>'
                     f'<rect x="{x:.1f}" y="{y_n:.1f}" width="{w:.1f}" height="{hn:.1f}" class="b-ok"/>'
                     f'<rect x="{x:.1f}" y="{y_n - hb:.1f}" width="{w:.1f}" height="{hb:.1f}" class="b-bad"/>'
                     f'</g>')
        if i % label_every == 0:
            fmt = "%d/%m" if size >= 86400 else "%H:%M"
            parts.append(f'<text x="{x + w / 2:.1f}" y="{H - 8}" class="axis" '
                         f'text-anchor="middle">{t.strftime(fmt)}</text>')
    parts.append("</svg>")
    unit = f"{size // 60} min" if size < 3600 else f"{size // 3600} h"
    return "".join(parts) + f'<p class="muted small">Cada barra = {unit}. Passe o mouse para ver os números.</p>'


def _alert_html(a: Alert, idx: int) -> str:
    cls = SEV_CLASS[a.severity]
    mitre = "".join(
        f'<a class="tag" href="{technique_url(t)}" target="_blank" rel="noopener">'
        f'{escape(t)} · {escape(technique_name(t))}</a>'
        for t in a.mitre
    )
    notes = "".join(f'<p class="note">⚠ {escape(n)}</p>' for n in a.notes)
    evidence = escape("\n".join(a.evidence(8)))
    search = escape(f"{a.rule_id} {a.title} {a.ip} {' '.join(a.mitre)}".lower())
    return f"""
<details class="alert sev-{cls}" data-sev="{cls}" data-search="{search}"{' open' if idx < 2 else ''}>
  <summary>
    <span class="badge {cls}">{a.severity.label}</span>
    <span class="rule">{escape(a.rule_id)}</span>
    <span class="title">{escape(a.title)}</span>
    <span class="ip">{escape(a.ip)}</span>
    <span class="when">{a.first_seen:%d/%m %H:%M} → {a.last_seen:%H:%M} · {a.count} evento(s)</span>
  </summary>
  <div class="body">
    <p>{escape(a.description)}</p>
    {notes}
    <div class="tags">{mitre}</div>
    <pre>{evidence}</pre>
  </div>
</details>"""


def to_html(events: Sequence[Event], alerts: Sequence[Alert], stats: Sequence[FileStats]) -> str:
    start, end = _period(events)
    attackers = rank_attackers(alerts)
    sev_counts = Counter(a.severity for a in alerts)

    sev_bar = "".join(
        f'<div class="seg {SEV_CLASS[s]}" style="flex:{sev_counts[s]}" '
        f'title="{s.label}: {sev_counts[s]}"></div>'
        for s in sorted(Severity, reverse=True) if sev_counts[s]
    ) or '<div class="seg none" style="flex:1"></div>'
    sev_legend = "".join(
        f'<li><span class="dot {SEV_CLASS[s]}"></span>{s.label}<b>{sev_counts[s]}</b></li>'
        for s in sorted(Severity, reverse=True)
    )

    tech_counts = Counter(t for a in alerts for t in a.mitre)
    tech_rows = "".join(
        f'<li><a href="{technique_url(t)}" target="_blank" rel="noopener">'
        f'<code>{escape(t)}</code> {escape(technique_name(t))}</a><b>{c}</b></li>'
        for t, c in tech_counts.most_common()
    ) or '<li class="muted">Nenhuma técnica observada.</li>'

    top_score = attackers[0].score if attackers else 1
    att_rows = "".join(
        f'<tr><td class="mono">{escape(a.ip)}</td>'
        f'<td><div class="score"><div class="fill {SEV_CLASS[a.max_severity]}" '
        f'style="width:{100 * a.score / top_score:.0f}%"></div><span>{a.score}</span></div></td>'
        f'<td><span class="badge {SEV_CLASS[a.max_severity]}">{a.max_severity.label}</span></td>'
        f'<td>{escape(", ".join(a.sources))}</td>'
        f'<td class="mono small">{escape(" ".join(a.rules))}</td>'
        f'<td class="num">{a.events}</td></tr>'
        for a in attackers[:15]
    ) or '<tr><td colspan="6" class="muted">Nenhum IP suspeito.</td></tr>'

    files = ", ".join(escape(s.path.rsplit("/", 1)[-1]) for s in stats)
    period = f"{start:%d/%m/%Y %H:%M} → {end:%d/%m/%Y %H:%M}" if start else "—"
    alerts_html = "".join(_alert_html(a, i) for i, a in enumerate(alerts)) or \
        '<p class="muted">Nenhum alerta. 🎉</p>'
    crit = sev_counts[Severity.CRITICA]
    n_events = f"{len(events):,}".replace(",", ".")

    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinela · Relatório de ameaças</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <div class="brand"><span class="logo">◆</span> SENTINELA <span class="ver">v{__version__}</span></div>
  <div class="meta">Período: <b>{period}</b> · Arquivos: <b>{files}</b> ·
  Gerado em {datetime.now():%d/%m/%Y %H:%M}</div>
</header>
<main>
  <section class="kpis">
    <div class="kpi"><span>Eventos analisados</span><b>{n_events}</b></div>
    <div class="kpi"><span>Alertas</span><b>{len(alerts)}</b></div>
    <div class="kpi {'crit' if crit else ''}"><span>Críticos</span><b>{crit}</b></div>
    <div class="kpi"><span>IPs hostis</span><b>{len(attackers)}</b></div>
    <div class="kpi"><span>Técnicas ATT&amp;CK</span><b>{len(tech_counts)}</b></div>
  </section>

  <section class="card">
    <h2>Linha do tempo <span class="legend"><i class="b-ok"></i>normal <i class="b-bad"></i>suspeito</span></h2>
    {_timeline_svg(events, alerts)}
  </section>

  <section class="grid2">
    <div class="card">
      <h2>Severidade dos alertas</h2>
      <div class="sevbar">{sev_bar}</div>
      <ul class="sevlegend">{sev_legend}</ul>
      <h2 class="mt">MITRE ATT&amp;CK observado</h2>
      <ul class="techs">{tech_rows}</ul>
    </div>
    <div class="card">
      <h2>Top atacantes <span class="muted small">pontuação = soma do peso das regras</span></h2>
      <div class="table-wrap"><table>
        <thead><tr><th>IP</th><th>Risco</th><th>Máx.</th><th>Fontes</th><th>Regras</th><th>Eventos</th></tr></thead>
        <tbody>{att_rows}</tbody>
      </table></div>
    </div>
  </section>

  <section class="card">
    <h2>Alertas <span class="muted small">({len(alerts)})</span></h2>
    <div class="filters">
      <input id="q" type="search" placeholder="Filtrar por IP, regra, técnica…">
      <button data-f="all" class="on">Todos</button>
      <button data-f="crit">Crítica</button>
      <button data-f="high">Alta</button>
      <button data-f="med">Média</button>
      <button data-f="low">Baixa</button>
    </div>
    <div id="alerts">{alerts_html}</div>
  </section>
</main>
<footer>Sentinela — detecção de ameaças em logs · mapeamento MITRE ATT&amp;CK®</footer>
<script>{_JS}</script>
</body>
</html>"""


_CSS = """
:root{--bg:#0b0f14;--panel:#121821;--panel2:#18202b;--line:#243041;--fg:#d8e1ec;--muted:#7d8ca0;
--crit:#ff4d6d;--high:#ff9f43;--med:#ffd166;--low:#4dabf7;--ok:#2f6f8f;--accent:#2ee6a6}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:center;justify-content:space-between;
padding:18px 28px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#0f151d,#0b0f14)}
.brand{font-weight:800;letter-spacing:.18em;font-size:18px}
.logo{color:var(--accent);text-shadow:0 0 12px var(--accent)}
.ver{font-weight:500;letter-spacing:0;color:var(--muted);font-size:12px}
.meta{color:var(--muted);font-size:13px}.meta b{color:var(--fg);font-weight:600}
main{max-width:1240px;margin:0 auto;padding:24px 20px 40px;display:grid;gap:20px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px}
.kpi span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.kpi b{display:block;font-size:30px;font-variant-numeric:tabular-nums}
.kpi.crit{border-color:var(--crit);box-shadow:0 0 0 1px var(--crit) inset,0 0 24px -8px var(--crit)}
.kpi.crit b{color:var(--crit)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;min-width:0}
h2{margin:0 0 14px;font-size:15px;font-weight:650;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
h2.mt{margin-top:22px}
.grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.6fr);gap:20px}
@media (max-width:900px){.grid2{grid-template-columns:1fr}}
.muted{color:var(--muted)}.small{font-size:12px;font-weight:400}
.mono,code,pre{font-family:ui-monospace,"JetBrains Mono",Consolas,monospace}
.timeline{width:100%;height:auto;display:block}
.timeline .grid{stroke:var(--line);stroke-dasharray:3 4}
.timeline .axis{fill:var(--muted);font-size:11px}
.b-ok{fill:var(--ok)}.b-bad{fill:var(--crit)}
.legend{font-size:12px;color:var(--muted);font-weight:400;display:flex;gap:6px;align-items:center}
.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-left:8px}
.legend i.b-ok{background:var(--ok)}.legend i.b-bad{background:var(--crit)}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;gap:2px;background:var(--panel2)}
.seg.crit{background:var(--crit)}.seg.high{background:var(--high)}.seg.med{background:var(--med)}.seg.low{background:var(--low)}
.sevlegend,.techs{list-style:none;padding:0;margin:12px 0 0;display:grid;gap:6px}
.sevlegend{grid-template-columns:repeat(2,1fr)}
.sevlegend li,.techs li{display:flex;align-items:center;gap:8px}
.sevlegend b,.techs b{margin-left:auto;font-variant-numeric:tabular-nums}
.techs a{color:var(--fg);text-decoration:none}.techs a:hover{color:var(--accent)}
.techs code{color:var(--accent);font-size:12px;margin-right:4px}
.dot{width:10px;height:10px;border-radius:50%}
.dot.crit{background:var(--crit)}.dot.high{background:var(--high)}.dot.med{background:var(--med)}.dot.low{background:var(--low)}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{color:var(--muted);font-weight:500;font-size:12px;text-transform:uppercase;letter-spacing:.06em;text-align:left;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:8px;border-bottom:1px solid var(--line);white-space:nowrap}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.score{position:relative;width:120px;height:18px;background:var(--panel2);border-radius:4px;overflow:hidden}
.score .fill{height:100%}.score span{position:absolute;inset:0;padding-left:6px;font-size:12px;line-height:18px;font-weight:600;color:#fff;text-shadow:0 1px 2px #000}
.fill.crit{background:var(--crit)}.fill.high{background:var(--high)}.fill.med{background:var(--med)}.fill.low{background:var(--low)}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.05em;padding:2px 8px;border-radius:999px;color:#0b0f14}
.badge.crit{background:var(--crit)}.badge.high{background:var(--high)}.badge.med{background:var(--med)}.badge.low{background:var(--low)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.filters input{flex:1 1 240px;background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 12px;font:inherit}
.filters button{background:var(--panel2);border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:6px 14px;cursor:pointer;font:inherit}
.filters button.on{border-color:var(--accent);color:var(--accent)}
.alert{border:1px solid var(--line);border-left:4px solid var(--line);border-radius:10px;margin-bottom:10px;background:var(--panel2)}
.alert.sev-crit{border-left-color:var(--crit)}.alert.sev-high{border-left-color:var(--high)}
.alert.sev-med{border-left-color:var(--med)}.alert.sev-low{border-left-color:var(--low)}
.alert summary{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;list-style:none}
.alert summary::-webkit-details-marker{display:none}
.rule{font-family:ui-monospace,monospace;color:var(--muted);font-size:12px}
.title{font-weight:600}
.ip{font-family:ui-monospace,monospace;color:var(--accent)}
.when{margin-left:auto;color:var(--muted);font-size:12px}
.body{padding:0 16px 14px}
.body p{margin:6px 0}
.note{color:var(--med)}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0}
.tag{font-size:12px;padding:3px 10px;border-radius:6px;background:#1d2a38;color:#9cc7ff;text-decoration:none;border:1px solid #2a3c52}
.tag:hover{border-color:#9cc7ff}
pre{background:#070a0e;border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-size:12px;color:#b9c7d8;margin:0}
footer{text-align:center;color:var(--muted);font-size:12px;padding:0 20px 30px}
"""

_JS = """
(function(){
  var q=document.getElementById('q'),btns=document.querySelectorAll('.filters button'),f='all';
  function apply(){
    var t=q.value.trim().toLowerCase();
    document.querySelectorAll('#alerts .alert').forEach(function(el){
      var ok=(f==='all'||el.dataset.sev===f)&&(!t||el.dataset.search.indexOf(t)>-1);
      el.hidden=!ok;
    });
  }
  btns.forEach(function(b){b.addEventListener('click',function(){
    btns.forEach(function(x){x.classList.remove('on')});b.classList.add('on');f=b.dataset.f;apply();
  })});
  q.addEventListener('input',apply);
})();
"""
