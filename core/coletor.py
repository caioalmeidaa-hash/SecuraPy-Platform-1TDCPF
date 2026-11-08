"""
Módulo 1 — Coletor de Logs (coletor.py)
Responsável por ler e parsear os arquivos de log das três fontes,
normalizando cada linha em um dicionário padronizado.

[2º semestre] Reaproveitado do SecuraPy CLI. Evoluções:
  - aceita DOIS formatos por fonte: o formato "real" (sshd / UFW / Apache) que
    a equipe usou no 1º semestre e o formato simplificado chave=valor dos logs
    oficiais da disciplina (ex.: "2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4");
  - adiciona o campo "timestamp_iso" (ISO 8601) para consultas por período no
    MongoDB e para a correlação temporal (bônus);
  - mensagens via logging em vez de print (a API roda como serviço).
"""

import logging
import os
import re
from datetime import datetime

log = logging.getLogger("securapy.core.coletor")

# Ano assumido para logs no formato syslog, que não trazem o ano ("Jun  1 02:10:01")
ANO_PADRAO_SYSLOG = int(os.getenv("SECURAPY_ANO_SYSLOG", "2025"))


# ── Regex compiladas para performance ────────────────────────────────────────

# auth.log — formato real do sshd
# Ex: Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2
# Ex: Jun  1 02:10:05 server sshd[1234]: Accepted password for carlos from 10.0.0.5 port 22 ssh2
_RE_AUTH_FAIL = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+Failed\s+\w+\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)"
)
_RE_AUTH_OK = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\S+)"
)

# auth.log — sudo privilege escalation
# Ex: Jun  1 02:13:45 server sudo[1300]: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash
_RE_AUTH_SUDO = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)\s+\S+\s+sudo\[\d+\]:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.+)"
)

# firewall.log — formato real do UFW
# Ex: Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= ... SRC=45.33.32.156 DST=10.0.0.1 ... PROTO=TCP DPT=22 SPT=60001
_RE_FW_BLOCK = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?).*\[UFW\s+(BLOCK|ALLOW)\].*SRC=(\S+).*DST=(\S+).*PROTO=(\S+).*DPT=(\d+)"
)

# web_access.log — formato Apache combined log
# Ex: 185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"
_RE_WEB = re.compile(
    r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(.+?)\s+HTTP/[\d.]+"\s+(\d+)\s+\S+(?:\s+"[^"]*")?\s+"([^"]*)"'
)


# ── Formato simplificado (logs oficiais da disciplina) ──────────────────────
_TS = r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
_RE_AUTH_SIMPLES = re.compile(_TS + r"\s+(FAIL|OK)\s+usuario=(\S+)\s+ip=(\S+)\s*$")
_RE_FW_SIMPLES = re.compile(
    _TS + r"\s+(BLOCK|ALLOW)\s+proto=(\S+)\s+src=(\S+)\s+dst=(\S+)\s+dport=(\d+)\s*$"
)
_RE_WEB_SIMPLES = re.compile(_TS + r"\s+([A-Z]+)\s+url=(.+?)\s+ip=(\S+)\s+status=(\d{3})\s*$")

# Formatos de data aceitos, em ordem de tentativa (tupla imutável)
_FORMATOS_DATA = (
    "%Y-%m-%d %H:%M:%S",          # 2025-02-20 08:15:01
    "%d/%b/%Y:%H:%M:%S %z",       # 01/Jun/2025:02:10:00 +0000 (Apache)
)


def normalizar_timestamp(timestamp):
    """
    Converte os diferentes formatos de data dos logs para ISO 8601.

    Retorna:
        str | None: "2025-02-20T08:15:01" ou None se não for possível converter
    """
    if not timestamp:
        return None
    texto = " ".join(str(timestamp).split())  # colapsa espaços duplos do syslog
    for formato in _FORMATOS_DATA:
        try:
            dt = datetime.strptime(texto, formato)
            return dt.replace(tzinfo=None).isoformat()
        except ValueError:
            continue
    try:  # ISO 8601 do rsyslog/journalctl moderno: "2026-11-08T20:10:01.123456-03:00"
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).replace(tzinfo=None, microsecond=0).isoformat()
    except ValueError:
        pass
    try:  # syslog: "Jun 1 02:10:01" (sem ano)
        dt = datetime.strptime(f"{ANO_PADRAO_SYSLOG} {texto}", "%Y %b %d %H:%M:%S")
        return dt.isoformat()
    except ValueError:
        return None


def _com_iso(evento):
    """Adiciona timestamp_iso a um evento já normalizado."""
    if evento is not None:
        evento["timestamp_iso"] = normalizar_timestamp(evento.get("timestamp"))
    return evento


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log (formato sshd OU simplificado)."""
    if not isinstance(linha, str):
        return None
    m = _RE_AUTH_SIMPLES.match(linha.strip())
    if m:
        usuario = m.group(3)
        return _com_iso({
            "timestamp": m.group(1),
            "fonte": "auth",
            "tipo": m.group(2),
            "ip": m.group(4),
            "detalhes": f"usuario={usuario}",
            "usuario": usuario,
            "linha_original": linha.strip(),
        })
    return _com_iso(_parsear_linha_auth_sshd(linha))


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log (formato UFW OU simplificado)."""
    if not isinstance(linha, str):
        return None
    m = _RE_FW_SIMPLES.match(linha.strip())
    if m:
        return _com_iso({
            "timestamp": m.group(1),
            "fonte": "firewall",
            "tipo": m.group(2),
            "ip": m.group(4),
            "detalhes": f"proto={m.group(3)} dst={m.group(5)} dport={m.group(6)}",
            "porta": int(m.group(6)),
            "linha_original": linha.strip(),
        })
    evento = _parsear_linha_firewall_ufw(linha)
    if evento and "dport=" in evento["detalhes"]:
        evento["porta"] = int(evento["detalhes"].split("dport=")[1].split()[0])
    return _com_iso(evento)


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log (formato Apache OU simplificado)."""
    if not isinstance(linha, str):
        return None
    m = _RE_WEB_SIMPLES.match(linha.strip())
    if m:
        metodo, url, ip, status = m.group(2), m.group(3), m.group(4), m.group(5)
        tipo = "FAIL" if status[0] in "45" else ("OK" if status[0] == "2" else "REQUEST")
        return _com_iso({
            "timestamp": m.group(1),
            "fonte": "web",
            "tipo": tipo,
            "ip": ip,
            "detalhes": f"metodo={metodo} url={url} status={status}",
            "url": url,
            "status": status,
            "user_agent": "",
            "linha_original": linha.strip(),
        })
    return _com_iso(_parsear_linha_web_apache(linha))


# Parsers originais do 1º semestre (mantidos sem alteração de comportamento)
PARSERS = {
    "auth": parsear_linha_auth,
    "firewall": parsear_linha_firewall,
    "web": parsear_linha_web,
}


def _parsear_linha_auth_sshd(linha):
    """
    Parseia uma linha do auth.log (formato real do sshd) e retorna dict normalizado.

    Formatos suportados:
      Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2
      Jun  1 02:10:05 server sshd[1234]: Accepted password for carlos from 10.0.0.5 port 22 ssh2
    """
    try:
        linha = linha.strip()
        if not linha:
            return None

        m = _RE_AUTH_FAIL.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "FAIL",
                "ip": m.group(3),
                "detalhes": f"usuario={m.group(2)}",
                "usuario": m.group(2),
                "linha_original": linha
            }

        m = _RE_AUTH_OK.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "OK",
                "ip": m.group(3),
                "detalhes": f"usuario={m.group(2)}",
                "linha_original": linha
            }

        m = _RE_AUTH_SUDO.search(linha)
        if m:
            return {
                "timestamp": m.group(1),
                "fonte": "auth",
                "tipo": "PRIVILEGE_ESCALATION",
                "ip": "local",
                "detalhes": f"usuario={m.group(2)} elevado_para={m.group(3)} comando={m.group(4).strip()}",
                "linha_original": linha
            }

        return None

    except Exception:
        return None


def _parsear_linha_firewall_ufw(linha):
    """
    Parseia uma linha do firewall.log (formato real do UFW) e retorna dict normalizado.

    Formato suportado:
      Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 ... SRC=45.33.32.156 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=60001
    """
    try:
        linha = linha.strip()
        if not linha:
            return None

        m = _RE_FW_BLOCK.search(linha)
        if m:
            timestamp = m.group(1)
            acao      = m.group(2)   # BLOCK ou ALLOW
            src       = m.group(3)
            dst       = m.group(4)
            proto     = m.group(5)
            dport     = m.group(6)

            tipo = "BLOCK" if acao == "BLOCK" else "ALLOW"

            return {
                "timestamp": timestamp,
                "fonte": "firewall",
                "tipo": tipo,
                "ip": src,
                "detalhes": f"proto={proto} dst={dst} dport={dport}",
                "linha_original": linha
            }

        return None

    except Exception:
        return None


def _parsear_linha_web_apache(linha):
    """
    Parseia uma linha do web_access.log (formato Apache combined) e retorna dict normalizado.

    Formato suportado:
      185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"
    """
    try:
        linha = linha.strip()
        if not linha:
            return None

        m = _RE_WEB.match(linha)
        if m:
            ip         = m.group(1)
            timestamp  = m.group(2)
            metodo     = m.group(3)
            url        = m.group(4)
            status     = m.group(5)
            user_agent = m.group(6)

            # Tipo baseado no status HTTP
            if status.startswith("4") or status.startswith("5"):
                tipo = "FAIL"
            elif status.startswith("2"):
                tipo = "OK"
            else:
                tipo = "REQUEST"

            return {
                "timestamp": timestamp,
                "fonte": "web",
                "tipo": tipo,
                "ip": ip,
                "detalhes": f"metodo={metodo} url={url} status={status}",
                "url": url,
                "status": status,
                "user_agent": user_agent,
                "linha_original": linha
            }

        return None

    except Exception:
        return None


def parsear_linhas(linhas, fonte, origem="<lote>"):
    """
    Parseia uma lista de linhas de uma fonte. Linhas mal formatadas são
    ignoradas com aviso — nunca interrompem o processamento.

    Retorna:
        tuple: (lista de eventos, quantidade de linhas ignoradas)
    """
    parser = PARSERS.get(fonte)
    if parser is None:
        log.warning("[AVISO] Fonte desconhecida: '%s'. Use: auth, firewall ou web.", fonte)
        return [], 0

    eventos, ignoradas = [], 0
    for numero, linha in enumerate(linhas, start=1):
        if not isinstance(linha, str) or not linha.strip():
            continue
        evento = parser(linha)
        if evento:
            eventos.append(evento)
        else:
            ignoradas += 1
            log.warning("[AVISO] Linha %d ignorada (formato inválido) em %s", numero, origem)
    return eventos, ignoradas


def carregar_log(caminho_arquivo, fonte):
    """
    Lê um arquivo de log e retorna lista de eventos normalizados.

    Parâmetros:
        caminho_arquivo (str): caminho para o arquivo de log
        fonte (str): tipo da fonte — "auth", "firewall" ou "web"

    Retorna:
        list[dict]: lista de eventos normalizados (vazia em caso de erro)
    """
    if fonte not in PARSERS:
        log.warning("[AVISO] Fonte desconhecida: '%s'. Use: auth, firewall ou web.", fonte)
        return []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8", errors="replace") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        log.error("[ERRO] Arquivo não encontrado: %s", caminho_arquivo)
        return []
    except PermissionError:
        log.error("[ERRO] Sem permissão para ler: %s", caminho_arquivo)
        return []
    except OSError as e:
        log.error("[ERRO] Falha ao ler %s: %s", caminho_arquivo, e.__class__.__name__)
        return []

    if not linhas:
        log.info("[INFO] Arquivo vazio: %s", caminho_arquivo)
        return []

    eventos, _ = parsear_linhas(linhas, fonte, origem=caminho_arquivo)
    log.info("[OK] Carregados %d eventos de %s", len(eventos), caminho_arquivo)
    return eventos


# Mapa nome de arquivo → fonte (reaproveitado em API e ingestão)
MAPA_ARQUIVOS = {
    "auth.log": "auth",
    "firewall.log": "firewall",
    "web_access.log": "web",
}


def carregar_todos_os_logs(pasta_logs):
    """
    Lê todos os arquivos de log conhecidos na pasta e retorna lista unificada.

    Parâmetros:
        pasta_logs (str): caminho para a pasta com os arquivos de log

    Retorna:
        list[dict]: lista unificada de todos os eventos normalizados
    """
    todos_os_eventos = []

    mapa_arquivos = MAPA_ARQUIVOS

    if not os.path.isdir(pasta_logs):
        log.error(f"[ERRO] Pasta de logs não encontrada: {pasta_logs}")
        return todos_os_eventos

    arquivos_na_pasta = os.listdir(pasta_logs)
    for nome_arquivo, fonte in mapa_arquivos.items():
        if nome_arquivo in arquivos_na_pasta:
            caminho = os.path.join(pasta_logs, nome_arquivo)
            eventos = carregar_log(caminho, fonte)
            todos_os_eventos.extend(eventos)
        else:
            log.warning(f"[AVISO] Arquivo esperado não encontrado na pasta: {nome_arquivo}")
    log.info(f"[RESUMO] Total de eventos carregados: {len(todos_os_eventos)}")
    return todos_os_eventos


# ─── Testes isolados do módulo ───────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Teste do Módulo 1 — Coletor de Logs ===\n")

    # Testa linhas individuais nos formatos reais
    print("--- Teste parsers com linhas reais ---")

    linha_auth_fail = 'Jun  1 02:10:01 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2'
    linha_auth_ok   = 'Jun  1 02:10:05 server sshd[999]: Accepted password for carlos from 10.0.0.5 port 22 ssh2'
    linha_fw        = 'Jun  1 02:10:00 fw kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=45.33.32.156 DST=10.0.0.1 PROTO=TCP DPT=22 SPT=60001'
    linha_web       = '185.220.101.1 - - [01/Jun/2025:02:10:00 +0000] "GET /admin/../../../etc/passwd HTTP/1.1" 403 512 "-" "Mozilla/5.0"'

    print("auth FAIL:", parsear_linha_auth(linha_auth_fail))
    print("auth OK:  ", parsear_linha_auth(linha_auth_ok))
    print("firewall: ", parsear_linha_firewall(linha_fw))
    print("web:      ", parsear_linha_web(linha_web))

    print("\n--- Carregar todos os logs ---")
    eventos = carregar_todos_os_logs("logs")

    print("\n--- Primeiros 3 eventos ---")
    for ev in eventos[:3]:
        print(ev)

    print("\n--- Teste com arquivo inexistente ---")
    carregar_log("logs/naoexiste.log", "auth")

    print("\n--- Teste com fonte inválida ---")
    carregar_log("logs/auth.log", "invalida")
