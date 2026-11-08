"""
Simulador de ataque em tempo real — para a demonstração ao vivo.

Gera linhas de log no formato REAL do Linux (sshd, UFW, Apache) com o horário
de agora e manda para POST /api/analisar a cada ~1,5 s. A tela "Ao vivo" do
dashboard reage sozinha: contadores sobem, alertas chegam, críticos piscam.

Uso (no Kali, com a plataforma no ar):
    python3 scripts/simular_ataque.py
    python3 scripts/simular_ataque.py --duracao 60 --intervalo 1
Só usa a biblioteca padrão do Python (não precisa instalar nada).
"""

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

INTERNOS = ["192.168.0.15", "192.168.0.22", "192.168.0.31", "192.168.0.40"]
USUARIOS = ["maria", "joao", "carla", "pedro"]
ATACANTES = ["203.0.113.66", "198.51.100.23", "192.0.2.77", "203.0.113.140", "45.33.32.156"]
PRIVILEGIADOS = ["root", "admin", "oracle", "sa", "administrator", "test"]
PORTAS = [21, 22, 23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 5432, 6379, 8080, 27017]
ATAQUES_WEB = [
    ("SQL Injection", "/produto?id=1 UNION SELECT usuario,senha FROM usuarios", "sqlmap/1.8"),
    ("SQL Injection", "/login?user=admin'--", "sqlmap/1.8"),
    ("XSS", "/busca?q=<script>alert(document.cookie)</script>", "Mozilla/5.0"),
    ("Path Traversal", "/download?arquivo=../../../../etc/passwd", "curl/8.5"),
    ("Scanner", "/wp-login.php", "Nikto/2.5.0"),
    ("Scanner", "/.env", "gobuster/3.6"),
]

COR = {"vermelho": "\033[91m", "amarelo": "\033[93m", "verde": "\033[92m", "ciano": "\033[96m",
       "cinza": "\033[90m", "negrito": "\033[1m", "fim": "\033[0m"}


def c(texto, *cores):
    return "".join(COR[x] for x in cores) + str(texto) + COR["fim"]


# ── geradores de linhas (formato real) ───────────────────────────────────────
def _syslog_ts(agora):
    return agora.strftime("%b ") + f"{agora.day:2d}" + agora.strftime(" %H:%M:%S")


def ssh(agora, ok, usuario, ip):
    resultado = "Accepted" if ok else "Failed"
    return {"fonte": "auth", "linha": f"{_syslog_ts(agora)} servidor sshd[{random.randint(1000, 9999)}]: "
                                      f"{resultado} password for {usuario} from {ip} port {random.randint(30000, 65000)} ssh2"}


def ufw(agora, acao, ip, porta):
    return {"fonte": "firewall", "linha": f"{_syslog_ts(agora)} servidor kernel: [UFW {acao}] IN=eth0 OUT= SRC={ip} "
                                          f"DST=10.0.0.5 PROTO=TCP SPT={random.randint(30000, 65000)} DPT={porta}"}


def web(agora, ip, url, status, ua):
    ts = agora.strftime("%d/%b/%Y:%H:%M:%S -0300")
    return {"fonte": "web", "linha": f'{ip} - - [{ts}] "GET {url} HTTP/1.1" {status} {random.randint(100, 9000)} "-" "{ua}"'}


# ── cenários ─────────────────────────────────────────────────────────────────
def trafego_normal(agora):
    linhas = []
    for _ in range(random.randint(2, 4)):
        i = random.randrange(len(INTERNOS))
        linhas.append(random.choice([
            ssh(agora, True, USUARIOS[i], INTERNOS[i]),
            ufw(agora, "ALLOW", INTERNOS[i], 443),
            web(agora, INTERNOS[i], random.choice(["/", "/produtos", "/contato", "/index.html"]), 200, "Mozilla/5.0"),
        ]))
    return "tráfego normal", None, linhas


def forca_bruta(agora):
    ip = random.choice(ATACANTES)
    return "força bruta SSH", ip, [ssh(agora, False, random.choice(PRIVILEGIADOS), ip) for _ in range(random.randint(5, 12))]


def port_scan(agora):
    ip = random.choice(ATACANTES)
    return "port scan", ip, [ufw(agora, "BLOCK", ip, p) for p in random.sample(PORTAS, random.randint(4, 9))]


def ataque_web(agora):
    ip = random.choice(ATACANTES)
    escolhidos = random.sample(ATAQUES_WEB, random.randint(2, 4))
    nomes = sorted({n for n, _, _ in escolhidos})
    linhas = [web(agora, ip, url, random.choice([200, 403, 404, 500]), ua) for _, url, ua in escolhidos]
    return "ataque web (" + ", ".join(nomes) + ")", ip, linhas


def ataque_completo(agora):
    ip = random.choice(ATACANTES)
    linhas = [ssh(agora, False, random.choice(PRIVILEGIADOS), ip) for _ in range(8)]
    linhas += [ufw(agora, "BLOCK", ip, p) for p in random.sample(PORTAS, 7)]
    linhas += [web(agora, ip, url, 500, ua) for _, url, ua in random.sample(ATAQUES_WEB, 3)]
    return "ATAQUE COMBINADO (força bruta + port scan + web)", ip, linhas


CENARIOS = [(trafego_normal, 35), (forca_bruta, 20), (port_scan, 15), (ataque_web, 20), (ataque_completo, 10)]


# ── API ──────────────────────────────────────────────────────────────────────
def post(url, corpo, token=None):
    cabecalhos = {"Content-Type": "application/json"}
    if token:
        cabecalhos["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(corpo).encode(), headers=cabecalhos, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def main():
    p = argparse.ArgumentParser(description="Simulador de ataque em tempo real para o SecuraPy")
    p.add_argument("--url", default="http://localhost:5000")
    p.add_argument("--email", default="admin@cybershield.com")
    p.add_argument("--senha", default="TroqueEsta123")
    p.add_argument("--intervalo", type=float, default=1.5, help="segundos entre ondas (padrão 1.5)")
    p.add_argument("--duracao", type=float, default=0, help="segundos de simulação (0 = até Ctrl+C)")
    a = p.parse_args()

    try:
        token = post(a.url + "/api/login", {"email": a.email, "senha": a.senha})["token"]
    except urllib.error.HTTPError as e:
        sys.exit(c(f"Login falhou (HTTP {e.code}). Confira --email e --senha.", "vermelho"))
    except urllib.error.URLError:
        sys.exit(c(f"Não consegui falar com {a.url}. A plataforma está no ar? (sudo docker compose ps)", "vermelho"))

    print(c("\n  SecuraPy — simulador de ataque em tempo real", "negrito"))
    print(c(f"  Enviando para {a.url}  ·  abra a tela 'Ao vivo' no navegador  ·  Ctrl+C para parar\n", "cinza"))

    inicio, ondas, total_alertas = time.time(), 0, 0
    try:
        while not a.duracao or time.time() - inicio < a.duracao:
            cenario = random.choices([f for f, _ in CENARIOS], weights=[w for _, w in CENARIOS])[0]
            nome, ip, linhas = cenario(datetime.now())
            try:
                r = post(a.url + "/api/analisar", {"eventos": linhas}, token)
            except urllib.error.HTTPError as e:
                if e.code == 401:  # token expirou: entra de novo
                    token = post(a.url + "/api/login", {"email": a.email, "senha": a.senha})["token"]
                    continue
                print(c(f"  erro HTTP {e.code}", "vermelho"))
                time.sleep(a.intervalo)
                continue
            ondas += 1
            sev = r.get("alertas_por_severidade", {})
            total_alertas += r.get("alertas_gerados", 0)
            hora = datetime.now().strftime("%H:%M:%S")
            resumo = "  ".join(f"{k}:{v}" for k, v in sorted(sev.items(), key=lambda kv: -len(kv[0])))
            cor = "vermelho" if sev.get("CRITICA") else "amarelo" if sev.get("ALTA") else "verde" if ip is None else "ciano"
            alvo = f" de {ip}" if ip else ""
            print(f"  {c(hora, 'cinza')}  {c(nome + alvo, cor, 'negrito' if sev.get('CRITICA') else 'fim')}"
                  f"  →  {len(linhas)} linhas, {r.get('alertas_gerados', 0)} alertas  {c(resumo, 'cinza')}")
            time.sleep(a.intervalo)
    except KeyboardInterrupt:
        pass
    print(c(f"\n  Fim: {ondas} ondas enviadas, {total_alertas} alertas gerados.\n", "negrito"))


if __name__ == "__main__":
    main()
