"""
SecuraPy — Coletor: conecta um servidor de verdade ao SecuraPy.

Instale no servidor que você quer proteger (o do seu site, da sua loja, da sua
startup). Ele acompanha os registros (logs) de login, firewall e site e manda
para o SecuraPy a cada 2 segundos. Só linhas de segurança saem do servidor:
login por SSH, bloqueios do firewall e acessos ao site — nada mais.

Uso mais simples (descobre sozinho onde estão os logs):
    sudo python3 coletor.py --url http://IP-DO-SECURAPY:5000 --email voce@empresa.com --auto

Escolhendo os arquivos:
    sudo python3 coletor.py --url ... --email ... --auth /var/log/auth.log --web /var/log/nginx/access.log

Só a biblioteca padrão do Python 3 (não precisa instalar nada). A senha é
pedida na hora (não fica no histórico) ou lida da variável SECURAPY_SENHA.
"""

import argparse
import getpass
import json
import os
import queue
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

CANDIDATOS = {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "firewall": ["/var/log/ufw.log"],
    "web": ["/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log"],
}
MAX_LOTE = 500
fila = queue.Queue()


# ── o que é linha de segurança ───────────────────────────────────────────────
def classificar(linha):
    """Devolve a fonte (auth/firewall) de uma linha do sistema, ou None se não interessa."""
    if ("sshd[" in linha or "sshd-session[" in linha) and (" Failed " in linha or " Accepted " in linha):
        return "auth"
    if "sudo[" in linha and "COMMAND=" in linha:
        return "auth"
    if "[UFW " in linha:
        return "firewall"
    return None


# ── leitores ─────────────────────────────────────────────────────────────────
def seguir_arquivo(caminho, fonte_fixa, parar):
    """Acompanha o arquivo como o 'tail -F': lê só o que for escrito daqui pra frente."""
    arquivo, inode = None, None
    while not parar.is_set():
        try:
            atual = os.stat(caminho).st_ino
            if arquivo is None or atual != inode:  # abriu agora ou o log foi rotacionado
                if arquivo:
                    arquivo.close()
                arquivo = open(caminho, encoding="utf-8", errors="replace")
                if inode is None:
                    arquivo.seek(0, os.SEEK_END)
                inode = atual
            linha = arquivo.readline()
            if not linha:
                time.sleep(0.5)
                continue
            linha = linha.rstrip("\n")
            # login: só linhas de SSH/sudo saem do servidor (privacidade); site/firewall: o arquivo todo é relevante
            fonte = classificar(linha) if fonte_fixa in (None, "auth") else fonte_fixa
            if fonte and linha.strip():
                fila.put({"fonte": fonte, "linha": linha[:4000]})
        except FileNotFoundError:
            time.sleep(2)
        except PermissionError:
            print(f"  ✗ Sem permissão para ler {caminho}. Rode com sudo.")
            return


def seguir_journal(parar):
    """Para sistemas sem /var/log/auth.log (ex.: Kali/Debian novos): lê o journal do systemd."""
    try:
        proc = subprocess.Popen(["journalctl", "-f", "-n", "0", "-o", "short-iso"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except FileNotFoundError:
        print("  ✗ journalctl não encontrado.")
        return
    for linha in proc.stdout:
        if parar.is_set():
            break
        fonte = classificar(linha)
        if fonte:
            fila.put({"fonte": fonte, "linha": linha.rstrip("\n")[:4000]})
    proc.terminate()


def descobrir_fontes():
    """--auto: usa os arquivos que existirem; sem auth.log, usa o journal."""
    fontes = []
    for fonte, caminhos in CANDIDATOS.items():
        for c in caminhos:
            if os.path.exists(c):
                fontes.append((fonte, c))
                break
    if not any(f == "auth" for f, _ in fontes):
        fontes.append(("journal", None))
    return fontes


# ── envio ────────────────────────────────────────────────────────────────────
def post(url, corpo, token=None):
    cab = {"Content-Type": "application/json"}
    if token:
        cab["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=json.dumps(corpo).encode(), headers=cab, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def entrar(url, email, senha):
    return post(url + "/api/login", {"email": email, "senha": senha})["token"]


def main():
    p = argparse.ArgumentParser(description="Coletor do SecuraPy: manda os logs de segurança deste servidor")
    p.add_argument("--url", required=True, help="endereço do SecuraPy, ex.: http://192.168.0.10:5000")
    p.add_argument("--email", required=True, help="email de um operador do SecuraPy (nível 3 ou mais)")
    p.add_argument("--senha", default=os.getenv("SECURAPY_SENHA"), help="(melhor deixar em branco: é perguntada)")
    p.add_argument("--auto", action="store_true", help="descobre sozinho onde estão os logs")
    p.add_argument("--auth", action="append", default=[], help="arquivo de login (ex.: /var/log/auth.log)")
    p.add_argument("--firewall", action="append", default=[], help="arquivo do firewall (ex.: /var/log/ufw.log)")
    p.add_argument("--web", action="append", default=[], help="log de acesso do site (Apache/Nginx)")
    p.add_argument("--journal", action="store_true", help="ler login/firewall do journal do systemd")
    p.add_argument("--nome", default=socket.gethostname(), help="nome deste servidor no painel")
    p.add_argument("--intervalo", type=float, default=2.0)
    a = p.parse_args()
    url = a.url.rstrip("/")
    senha = a.senha or getpass.getpass(f"Senha do SecuraPy para {a.email}: ")

    try:
        token = entrar(url, a.email, senha)
    except urllib.error.HTTPError as e:
        sys.exit(f"✗ Login recusado (HTTP {e.code}). Confira email e senha.")
    except urllib.error.URLError:
        sys.exit(f"✗ Não consegui falar com {url}. O SecuraPy está no ar e acessível deste servidor?")

    fontes = [("auth", f) for f in a.auth] + [("firewall", f) for f in a.firewall] + [("web", f) for f in a.web]
    if a.journal:
        fontes.append(("journal", None))
    if a.auto or not fontes:
        fontes += [f for f in descobrir_fontes() if f not in fontes]

    print(f"\n  SecuraPy — coletor conectado a {url} como '{a.nome}'")
    parar = threading.Event()
    for fonte, caminho in fontes:
        if fonte == "journal":
            print("  • lendo login (SSH) e firewall do journal do sistema")
            threading.Thread(target=seguir_journal, args=(parar,), daemon=True).start()
        else:
            print(f"  • lendo {fonte:8s} de {caminho}")
            threading.Thread(target=seguir_arquivo, args=(caminho, fonte, parar), daemon=True).start()
    print("  Acompanhando em tempo real… (Ctrl+C para parar)\n")

    total = 0
    try:
        while True:
            time.sleep(a.intervalo)
            lote = []
            while not fila.empty() and len(lote) < MAX_LOTE:
                lote.append(fila.get_nowait())
            if not lote:
                continue
            corpo = {"eventos": lote, "coletor": a.nome}
            try:
                r = post(url + "/api/analisar", corpo, token)
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    token = entrar(url, a.email, senha)
                    r = post(url + "/api/analisar", corpo, token)
                else:
                    print(f"  ✗ SecuraPy respondeu HTTP {e.code}; as linhas deste lote foram descartadas.")
                    continue
            except urllib.error.URLError:
                print("  ✗ SecuraPy fora do ar; tentando de novo no próximo ciclo.")
                for item in lote:
                    fila.put(item)
                continue
            total += len(lote)
            sev = r.get("alertas_por_severidade", {})
            resumo = ", ".join(f"{k}:{v}" for k, v in sev.items()) or "nenhum alerta"
            print(f"  {time.strftime('%H:%M:%S')}  {len(lote)} linhas enviadas → {r.get('alertas_gerados', 0)} alertas ({resumo})")
    except KeyboardInterrupt:
        parar.set()
        print(f"\n  Coletor parado. {total} linhas enviadas.\n")


if __name__ == "__main__":
    main()
