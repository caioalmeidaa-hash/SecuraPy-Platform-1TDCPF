"""
Autenticação por token (2º sem — Aula 10) — BÔNUS: JWT completo.

  - POST /api/login devolve um JWT (HS256) assinado com JWT_SECRET (env),
    com exp, iat, iss, aud e o nível de acesso do operador.
  - requer_token(nivel_minimo) protege as rotas: sem header
    "Authorization: Bearer <token>" válido → 401; nível insuficiente → 403.
  - Algoritmo fixo na verificação (algorithms=["HS256"]) → bloqueia o ataque
    "alg: none" / troca de algoritmo.
  - Limite de tentativas de login por IP+email (anti força-bruta).
"""

import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

EMISSOR = "securapy-platform"
AUDIENCIA = "securapy-api"
ALGORITMO = "HS256"


def segredo_jwt():
    return current_app.config["JWT_SECRET"]


def gerar_token(usuario, minutos=None):
    minutos = minutos or current_app.config.get("JWT_EXPIRA_MINUTOS", 60)
    agora = datetime.now(timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "email": usuario["email"],
        "nome": usuario["nome"],
        "nivel": int(usuario["nivel_acesso"]),
        "iat": agora,
        "exp": agora + timedelta(minutes=minutos),
        "iss": EMISSOR,
        "aud": AUDIENCIA,
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, segredo_jwt(), algorithm=ALGORITMO), payload["exp"].isoformat()


def verificar_token(token):
    """Retorna o payload se o token for válido; senão None (nunca levanta exceção)."""
    try:
        return jwt.decode(token, segredo_jwt(), algorithms=[ALGORITMO], audience=AUDIENCIA, issuer=EMISSOR,
                          options={"require": ["exp", "iat", "sub", "iss", "aud"]})
    except jwt.PyJWTError:
        return None


def _token_do_header():
    cabecalho = request.headers.get("Authorization", "")
    tipo, _, token = cabecalho.partition(" ")
    if tipo.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def requer_token(nivel_minimo=1):
    """Decorator: exige JWT válido e nível de acesso >= nivel_minimo."""
    def decorador(funcao):
        @wraps(funcao)
        def interna(*args, **kwargs):
            token = _token_do_header()
            payload = verificar_token(token) if token else None
            if payload is None:
                resposta = jsonify(erro="Token ausente ou inválido")
                resposta.headers["WWW-Authenticate"] = 'Bearer realm="securapy"'
                return resposta, 401
            if int(payload.get("nivel", 0)) < nivel_minimo:
                return jsonify(erro="Permissão insuficiente"), 403
            g.usuario = payload
            return funcao(*args, **kwargs)
        return interna
    return decorador


class LimitadorTentativas:
    """Bloqueia após N falhas de login na janela (por chave IP+email). Memória do processo."""

    def __init__(self, maximo=5, janela_segundos=300):
        self.maximo = maximo
        self.janela = janela_segundos
        self._falhas = {}
        self._lock = threading.Lock()

    def _recentes(self, chave, agora):
        return [t for t in self._falhas.get(chave, []) if agora - t < self.janela]

    def bloqueado(self, chave):
        with self._lock:
            return len(self._recentes(chave, time.time())) >= self.maximo

    def registrar_falha(self, chave):
        with self._lock:
            agora = time.time()
            self._falhas[chave] = self._recentes(chave, agora) + [agora]

    def limpar(self, chave):
        with self._lock:
            self._falhas.pop(chave, None)


def segredo_ou_aleatorio(nome_env, app_logger):
    valor = os.getenv(nome_env)
    if valor and len(valor) >= 32:
        return valor
    app_logger.warning("%s ausente ou curto (<32); usando segredo aleatório (tokens/sessões não "
                       "sobrevivem a reinício)", nome_env)
    return secrets.token_urlsafe(48)
