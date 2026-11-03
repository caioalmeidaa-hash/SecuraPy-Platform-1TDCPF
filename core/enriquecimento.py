"""
Módulo 5 — Enriquecimento de IPs (enriquecimento.py)
Consulta a API pública do ipinfo.io para obter geolocalização
e informações de cada IP suspeito. Usa cache para evitar
chamadas repetidas à API.

[2º semestre] Reaproveitado do SecuraPy CLI. Melhorias:
  - eh_ip_privado() usa o módulo ipaddress (cobre RFC 1918, loopback,
    link-local, reservados e IPv6) e trata IP malformado;
  - token opcional via variável de ambiente IPINFO_TOKEN, enviado no header
    (nunca na URL, para não vazar em logs);
  - modo offline (ENRIQUECIMENTO_OFFLINE=1) para laboratório sem internet;
  - cache com TTL (padrão 24h) para não servir dado velho para sempre;
  - erros de rede nunca propagam exceção: devolvem um resultado "vazio".
"""

import ipaddress
import logging
import os
import time

import requests

log = logging.getLogger("securapy.core.enriquecimento")

URL_IPINFO = "https://ipinfo.io/{ip}/json"
TIMEOUT_SEGUNDOS = 5
TTL_CACHE_SEGUNDOS = int(os.getenv("ENRIQUECIMENTO_TTL", "86400"))


def ip_valido(ip):
    """Retorna True se a string for um endereço IPv4/IPv6 válido."""
    try:
        ipaddress.ip_address(str(ip).strip())
        return True
    except ValueError:
        return False


def eh_ip_privado(ip):
    """
    Verifica se um IP é de rede interna (RFC 1918, loopback, link-local...).

    Retorna:
        bool: True se privado/reservado, False se público ou inválido
    """
    try:
        endereco = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return endereco.is_private or endereco.is_loopback or endereco.is_link_local


def _offline():
    return os.getenv("ENRIQUECIMENTO_OFFLINE", "0").lower() in ("1", "true", "sim")


def _resultado_vazio(ip, motivo="Dados indisponíveis"):
    """Dict padronizado quando a consulta não é possível."""
    return {
        "ip": ip,
        "cidade": "N/A",
        "regiao": "N/A",
        "pais": "N/A",
        "org": "N/A",
        "hostname": "N/A",
        "privado": False,
        "descricao": motivo,
    }


def consultar_ip(ip, cache):
    """
    Consulta o ipinfo.io para obter dados de geolocalização do IP.
    Usa cache (dicionário {ip: (instante, dados)}) para evitar consultas repetidas.

    Retorna:
        dict: {ip, cidade, regiao, pais, org, hostname, privado, descricao}
    """
    if not ip_valido(ip):
        return _resultado_vazio(str(ip), "IP inválido")

    if eh_ip_privado(ip):
        resultado = _resultado_vazio(ip, "Rede Interna (IP Privado)")
        resultado["privado"] = True
        return resultado

    entrada = cache.get(ip)
    if entrada and time.time() - entrada[0] < TTL_CACHE_SEGUNDOS:
        log.debug("[CACHE] IP %s retornado do cache", ip)
        return entrada[1]

    if _offline():
        return _resultado_vazio(ip, "Enriquecimento offline")

    cabecalhos = {"Accept": "application/json"}
    token = os.getenv("IPINFO_TOKEN")
    if token:
        cabecalhos["Authorization"] = f"Bearer {token}"

    try:
        resposta = requests.get(URL_IPINFO.format(ip=ip), headers=cabecalhos, timeout=TIMEOUT_SEGUNDOS)
    except requests.exceptions.ConnectionError:
        log.error("[ERRO] Sem conexão ao consultar %s", ip)
        return _resultado_vazio(ip, "Sem conexão")
    except requests.exceptions.Timeout:
        log.error("[ERRO] Timeout ao consultar %s", ip)
        return _resultado_vazio(ip, "Timeout na requisição")
    except requests.exceptions.RequestException as e:
        log.error("[ERRO] Falha ao consultar %s (%s)", ip, e.__class__.__name__)
        return _resultado_vazio(ip, "Erro de requisição")

    if resposta.status_code == 429:
        log.warning("[AVISO] Limite de requisições atingido para %s", ip)
        return _resultado_vazio(ip, "Limite de API atingido")
    if resposta.status_code != 200:
        log.warning("[AVISO] API retornou status %s para %s", resposta.status_code, ip)
        return _resultado_vazio(ip, f"Erro HTTP {resposta.status_code}")

    try:
        dados = resposta.json()
    except ValueError:
        return _resultado_vazio(ip, "Resposta inválida da API")

    resultado = {
        "ip": ip,
        "cidade": dados.get("city", "Desconhecida"),
        "regiao": dados.get("region", "Desconhecida"),
        "pais": dados.get("country", "Desconhecido"),
        "org": dados.get("org", "Desconhecida"),
        "hostname": dados.get("hostname", "N/A"),
        "privado": False,
        "descricao": f"{dados.get('city', '?')}, {dados.get('country', '?')} — {dados.get('org', '?')}",
    }
    cache[ip] = (time.time(), resultado)
    log.info("[OK] IP %s enriquecido: %s", ip, resultado["descricao"])
    return resultado


def enriquecer_alertas(alertas, cache):
    """
    Adiciona o campo "geo" a cada alerta (usa cache; IPs privados não saem da rede).

    Retorna:
        list[dict]: novos dicts de alerta com o campo "geo"
    """
    return [dict(alerta, geo=consultar_ip(alerta.get("ip", ""), cache)) for alerta in alertas]
