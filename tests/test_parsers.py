import gzip
from datetime import datetime

from sentinela.parsers import parse_files, parse_line


def test_ssh_failed_syslog():
    e = parse_line("Nov 24 03:12:01 srv sshd[812]: Failed password for root from 203.0.113.45 port 50122 ssh2", 2026)
    assert e.source == "ssh" and e.action == "failed"
    assert e.user == "root" and e.ip == "203.0.113.45" and not e.invalid_user
    assert e.timestamp == datetime(2026, 11, 24, 3, 12, 1)


def test_ssh_failed_invalid_user():
    e = parse_line("Nov  4 05:40:00 srv sshd[1]: Failed password for invalid user oracle from 198.51.100.23 port 4444 ssh2", 2026)
    assert e.user == "oracle" and e.invalid_user
    assert e.timestamp.day == 4


def test_ssh_accepted_iso_and_sshd_session():
    line = ("2026-11-24T14:06:42.123456-03:00 srv sshd-session[999]: "
            "Accepted password for deploy from 192.0.2.77 port 5555 ssh2")
    e = parse_line(line, 2000)
    assert e.action == "accepted" and e.user == "deploy"
    assert e.timestamp == datetime(2026, 11, 24, 14, 6, 42)


def test_ssh_ipv6():
    e = parse_line("Nov 24 03:12:01 srv sshd[812]: Failed password for root from 2001:db8::1 port 22 ssh2", 2026)
    assert e.ip == "2001:db8::1"


def test_irrelevant_lines_are_ignored():
    assert parse_line("Nov 24 03:12:01 srv sshd[812]: Connection closed by 10.0.0.1 port 22", 2026) is None
    assert parse_line("Nov 24 03:12:01 srv CRON[1]: (root) CMD (run-parts)", 2026) is None
    assert parse_line("", 2026) is None
    assert parse_line("lixo qualquer", 2026) is None


def test_web_combined():
    line = ('203.0.113.10 - - [24/Nov/2026:02:00:01 -0300] "GET /.env HTTP/1.1" 404 290 '
            '"-" "Mozilla/5.00 (Nikto/2.5.0)"')
    e = parse_line(line, 2026)
    assert e.source == "web" and e.method == "GET" and e.path == "/.env"
    assert e.status == 404 and "Nikto" in e.user_agent
    assert e.timestamp == datetime(2026, 11, 24, 2, 0, 1)


def test_web_escaped_quotes_in_user_agent():
    line = ('192.0.2.1 - - [24/Nov/2026:02:00:01 +0000] "GET / HTTP/1.1" 200 10 '
            '"-" "x\\" onmouseover=\\"alert(1)"')
    e = parse_line(line, 2026)
    assert e.user_agent == 'x" onmouseover="alert(1)'


def test_web_malformed_request_line():
    line = '192.0.2.1 - - [24/Nov/2026:02:00:01 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"'
    e = parse_line(line, 2026)
    assert e is not None and e.method is None and e.status == 400


def test_parse_files_sorts_and_reads_gz(tmp_path):
    plain = tmp_path / "auth.log"
    plain.write_text(
        "Nov 24 10:00:00 s sshd[1]: Failed password for a from 192.0.2.1 port 1 ssh2\n"
        "nada a ver\n"
    )
    gz = tmp_path / "auth.log.1.gz"
    with gzip.open(gz, "wt") as fh:
        fh.write("Nov 24 09:00:00 s sshd[1]: Failed password for b from 192.0.2.1 port 1 ssh2\n")

    events, stats = parse_files([plain, gz], year=2026)
    assert [e.user for e in events] == ["b", "a"]
    assert stats[0].lines == 2 and stats[0].parsed == 1 and stats[0].ignored == 1
    assert events[1].line_no == 1 and events[1].file == "auth.log"
