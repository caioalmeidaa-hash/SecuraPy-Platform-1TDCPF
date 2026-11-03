"""
Pipeline do núcleo (2º semestre).

Junta, em uma única chamada reutilizável, o fluxo que no 1º semestre ficava
espalhado na opção 1 do menu do main.py:

    eventos → regras → detector (brute force, port scan, blacklist, janela)

Não conhece banco, ML nem HTTP — só o núcleo. As camadas de cima
(api/servico.py e scripts/ingerir.py) usam este módulo.
"""

import os

from core.coletor import carregar_todos_os_logs
from core.detector import (
    carregar_blacklist,
    detectar_brute_force,
    detectar_brute_force_janela,
    detectar_port_scan,
    gerar_resumo_ameacas,
    verificar_blacklist,
)
from core.regras import aplicar_regras, carregar_regras

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAMINHO_REGRAS = os.getenv("SECURAPY_REGRAS", os.path.join(RAIZ, "config", "regras.json"))
CAMINHO_BLACKLIST = os.getenv("SECURAPY_BLACKLIST", os.path.join(RAIZ, "config", "blacklist.json"))
PASTA_LOGS = os.getenv("SECURAPY_LOGS", os.path.join(RAIZ, "logs"))

# Correlações viram alertas com IDs próprios (C = correlação)
_CORRELACOES = {
    "brute_force": ("C001", "Brute Force (correlação)", "Múltiplas falhas de login do mesmo IP"),
    "port_scan": ("C002", "Port Scan (correlação)", "Muitas portas distintas bloqueadas para o mesmo IP"),
    "blacklist": ("C003", "IP em Blacklist", "IP presente na lista de ameaças conhecidas"),
    "janela": ("C004", "Brute Force em janela de tempo", "Rajada de falhas de login em janela curta"),
    "consolidada": ("C005", "Ameaça consolidada", "IP com múltiplas detecções combinadas"),
}


def _ultimo_evento_do_ip(eventos, ip):
    for evento in reversed(eventos):
        if evento.get("ip") == ip:
            return evento
    return {}


def _alerta_correlacao(chave, ip, severidade, detalhe, eventos):
    regra_id, nome, descricao = _CORRELACOES[chave]
    ultimo = _ultimo_evento_do_ip(eventos, ip)
    return {
        "timestamp": ultimo.get("timestamp", ""),
        "timestamp_iso": ultimo.get("timestamp_iso"),
        "regra_id": regra_id,
        "regra_nome": nome,
        "severidade": severidade,
        "pontuacao": {"CRITICA": 9, "ALTA": 7, "MEDIA": 5, "BAIXA": 3}.get(severidade, 1),
        "ip": ip,
        "fonte": "correlacao",
        "descricao": f"{descricao}: {detalhe}",
        "evento_original": "",
        "origem": "detector",
    }


def alertas_de_correlacao(eventos, brute_force, port_scan, ips_blacklist, janela, ameacas=()):
    """Converte as detecções do detector em alertas (mesmo contrato dos alertas de regra)."""
    alertas = []
    for ip, d in brute_force.items():
        alertas.append(_alerta_correlacao("brute_force", ip, d["severidade"],
                                          f"{d['tentativas']} falhas ({', '.join(d['usuarios'])})", eventos))
    for ip, d in port_scan.items():
        portas = ",".join(str(p) for p in sorted(d["portas"]))
        alertas.append(_alerta_correlacao("port_scan", ip, d["severidade"],
                                          f"{d['quantidade']} portas ({portas})", eventos))
    for ip in sorted(ips_blacklist):
        alertas.append(_alerta_correlacao("blacklist", ip, "ALTA", ip, eventos))
    for ip, d in janela.items():
        alertas.append(_alerta_correlacao("janela", ip, "ALTA",
                                          f"{d['max_na_janela']} falhas em {d['janela_segundos']}s", eventos))
    for ameaca in ameacas:  # resumo do detector (1º sem) também vira alerta, com a severidade consolidada
        if len(ameaca["motivos"]) > 1:
            alertas.append(_alerta_correlacao("consolidada", ameaca["ip"], ameaca["severidade"],
                                              "; ".join(ameaca["motivos"]), eventos))
    return alertas


def analisar_eventos(eventos, regras=None, blacklist=None):
    """
    Roda regras + detector sobre uma lista de eventos já normalizados.

    Retorna:
        dict com: eventos, alertas (regras + correlações), ameacas (resumo
        ordenado do detector) e deteccoes (dados brutos, serializáveis)
    """
    regras = regras if regras is not None else carregar_regras(CAMINHO_REGRAS)
    blacklist = blacklist if blacklist is not None else carregar_blacklist(CAMINHO_BLACKLIST)

    alertas = aplicar_regras(eventos, regras)
    brute_force = detectar_brute_force(eventos)
    port_scan = detectar_port_scan(eventos)
    ips_blacklist, contagem_blacklist = verificar_blacklist(eventos, blacklist)
    janela = detectar_brute_force_janela(eventos)
    ameacas = gerar_resumo_ameacas(brute_force, port_scan, ips_blacklist)

    alertas += alertas_de_correlacao(eventos, brute_force, port_scan, ips_blacklist, janela, ameacas)

    return {
        "eventos": eventos,
        "alertas": alertas,
        "ameacas": ameacas,
        "deteccoes": {
            "brute_force": brute_force,
            "port_scan": {ip: {**d, "portas": sorted(d["portas"])} for ip, d in port_scan.items()},
            "blacklist": {"ips": sorted(ips_blacklist), "contagem": contagem_blacklist},
            "brute_force_janela": janela,
        },
    }


def analisar_pasta(pasta_logs=PASTA_LOGS, regras=None, blacklist=None):
    """Atalho: carrega os 3 logs de uma pasta e analisa."""
    return analisar_eventos(carregar_todos_os_logs(pasta_logs), regras, blacklist)
