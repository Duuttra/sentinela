"""A ferramenta lê dados controlados pelo atacante: ela própria precisa ser robusta."""

import time

from sentinela.cli import main, safe
from sentinela.detectors import SIGNATURES, _decode

MAX_LINE = 8190  # limite padrão da linha de requisição no Apache/Nginx


def test_safe_neutralizes_terminal_escape_sequences():
    evil = "root\x1b]0;pwned\x07\x1b[2J\x9b31m\x7f"
    out = safe(evil)
    assert all(ord(c) >= 0x20 and not (0x7F <= ord(c) < 0xA0) for c in out)
    assert out.startswith("root") and "\\x1b" in out


def test_safe_keeps_normal_text():
    assert safe("usuário 'deploy' — São Paulo ✓") == "usuário 'deploy' — São Paulo ✓"


def test_cli_output_has_no_injected_escape_sequences(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("".join(
        f"Nov 24 03:00:{i:02d} s sshd[1]: Failed password for invalid user "
        f"x\x1b[2J\x1b]0;pwned\x07 from 203.0.113.9 port 1 ssh2\n"
        for i in range(12)
    ))
    main(["analisar", str(log), "--ano", "2026", "--sem-cor"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "SSH-001" in out


def test_signatures_resist_redos():
    payloads = ["<svg " * (MAX_LINE // 5), "' or " * (MAX_LINE // 5), "../" * (MAX_LINE // 3),
                "${" * (MAX_LINE // 2), "%25" * (MAX_LINE // 3), "onerror" * (MAX_LINE // 7)]
    start = time.perf_counter()
    for p in payloads:
        for sig in SIGNATURES:
            sig.regex.search(_decode(p) + "\n" + p)
    assert time.perf_counter() - start < 0.5
