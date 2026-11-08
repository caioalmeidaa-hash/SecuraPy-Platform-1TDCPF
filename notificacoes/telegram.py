"""
Alertas no celular pelo Telegram — em linguagem simples.

Pequena empresa não fica olhando painel, mas olha o celular. Quando chega um
alerta CRÍTICO, o dono recebe uma mensagem curta dizendo o que aconteceu e
um link para ver os detalhes.

Configuração (.env):  TELEGRAM_BOT_TOKEN=...   TELEGRAM_CHAT_ID=...
Sem essas variáveis, nada é enviado (e nada quebra).

Anti-spam: 1 mensagem a cada 2 minutos por atacante e no máximo 10 por minuto.
O envio roda numa thread separada para não atrasar a análise.
"""

import logging
import os
import threading
import time

import requests

log = logging.getLogger("securapy.telegram")

API = "https://api.telegram.org/bot{token}/{metodo}"
INTERVALO_POR_IP = 120
MAX_POR_MINUTO = 10

FRASES = {
    "R001": "Alguém tentou entrar no seu servidor com uma conta de administrador",
    "R003": "Alguém tentou ler arquivos secretos do seu servidor",
    "R004": "Alguém tentou colocar código malicioso no seu site",
    "R006": "Alguém tentou roubar dados do banco de dados do seu site",
    "C001": "Alguém está tentando adivinhar as senhas do seu servidor",
    "C004": "Alguém está tentando adivinhar senhas muito rápido",
    "C005": "Um mesmo endereço está fazendo vários tipos de ataque ao mesmo tempo",
}

_ultimo_por_ip = {}
_envios_recentes = []
_trava = threading.Lock()


def configurado():
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"))


def enviar(texto, token=None, chat_id=None):
    """Envia uma mensagem. Retorna (ok, detalhe) — nunca levanta exceção."""
    token = token or os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False, "Telegram não configurado (faltam TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID no .env)."
    try:
        r = requests.post(API.format(token=token, metodo="sendMessage"), timeout=10,
                          json={"chat_id": chat_id, "text": texto[:3500], "disable_web_page_preview": True})
        if r.status_code == 200 and r.json().get("ok"):
            return True, "Mensagem enviada."
        descricao = (r.json() or {}).get("description", "") if r.headers.get("content-type", "").startswith("application/json") else ""
        return False, f"O Telegram recusou (HTTP {r.status_code}). {descricao}".strip()
    except (requests.RequestException, ValueError) as e:
        return False, f"Não consegui falar com o Telegram ({e.__class__.__name__})."


def descobrir_chats(token=None):
    """Lista os chats que mandaram mensagem ao bot (para achar o TELEGRAM_CHAT_ID)."""
    token = token or os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        return False, "Falta o TELEGRAM_BOT_TOKEN no .env.", []
    try:
        r = requests.get(API.format(token=token, metodo="getUpdates"), timeout=10)
        dados = r.json()
    except (requests.RequestException, ValueError) as e:
        return False, f"Não consegui falar com o Telegram ({e.__class__.__name__}).", []
    if not dados.get("ok"):
        return False, "Token recusado pelo Telegram. Confira o TELEGRAM_BOT_TOKEN.", []
    chats = {}
    for u in dados.get("result", []):
        chat = (u.get("message") or u.get("channel_post") or {}).get("chat") or {}
        if chat.get("id") is not None:
            nome = chat.get("title") or " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x)
            chats[chat["id"]] = nome or chat.get("username") or "sem nome"
    if not chats:
        return False, "Nenhuma conversa encontrada. Abra o seu bot no Telegram, mande um 'oi' e tente de novo.", []
    return True, "Encontrei as conversas abaixo.", [{"id": k, "nome": v} for k, v in chats.items()]


def montar_mensagem(ip, alertas):
    frases = []
    for a in alertas:
        frase = FRASES.get(a.get("regra_id"), a.get("regra_nome") or "Ataque crítico detectado")
        if frase not in frases:
            frases.append(frase)
    url = os.getenv("SECURAPY_URL_PUBLICA", "http://localhost:5000").rstrip("/")
    return ("🚨 SecuraPy — alerta CRÍTICO\n\n"
            + "\n".join(f"• {f}." for f in frases[:4])
            + f"\n\nEndereço do atacante: {ip}\n\n"
              "O que fazer: abra o link, veja a ficha do atacante e clique em “Diagnosticar com IA” "
              "para saber onde está a brecha e como fechar.\n"
            + f"{url}/ip?ip={ip}")


def notificar_criticos(alertas):
    """Chamado após cada análise. Agrupa os críticos por IP e aplica o anti-spam."""
    if not configurado():
        return 0
    por_ip = {}
    for a in alertas:
        if a.get("severidade") == "CRITICA" and a.get("ip"):
            por_ip.setdefault(a["ip"], []).append(a)
    agora, mensagens = time.time(), []
    with _trava:
        _envios_recentes[:] = [t for t in _envios_recentes if agora - t < 60]
        for ip, lista in por_ip.items():
            if agora - _ultimo_por_ip.get(ip, 0) < INTERVALO_POR_IP or len(_envios_recentes) >= MAX_POR_MINUTO:
                continue
            _ultimo_por_ip[ip] = agora
            _envios_recentes.append(agora)
            mensagens.append(montar_mensagem(ip, lista))
    for texto in mensagens:
        threading.Thread(target=_enviar_e_registrar, args=(texto,), daemon=True).start()
    return len(mensagens)


def _enviar_e_registrar(texto):
    ok, detalhe = enviar(texto)
    if not ok:
        log.warning("Alerta no Telegram não enviado: %s", detalhe)
