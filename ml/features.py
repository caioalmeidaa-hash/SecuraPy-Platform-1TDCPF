"""
Extração de features por IP (2º sem — Aula 4).

Cada IP vira um vetor numérico com o "comportamento" dele nos logs.
O mesmo código é usado no treino e na classificação — assim não há
divergência entre o que o modelo aprendeu e o que ele recebe.
"""

from core.enriquecimento import eh_ip_privado

# Ordem fixa das features (tupla = imutável; o modelo depende dessa ordem)
FEATURES = (
    "falhas_login",
    "logins_ok",
    "usuarios_distintos",
    "portas_distintas",
    "bloqueios_firewall",
    "web_erros",
    "web_total",
    "alertas_regras",
    "em_blacklist",
    "ip_privado",
)


def _vazio():
    return {"falhas_login": 0, "logins_ok": 0, "usuarios": set(), "portas": set(),
            "bloqueios_firewall": 0, "web_erros": 0, "web_total": 0, "alertas_regras": 0}


def extrair_features(eventos, alertas=(), blacklist=frozenset()):
    """
    Agrega eventos e alertas por IP.

    Retorna:
        dict: {ip: {feature: valor}} com as chaves de FEATURES
    """
    brutos = {}
    for evento in eventos:
        ip = evento.get("ip")
        if not ip or ip in ("local", "desconhecido"):
            continue
        b = brutos.setdefault(ip, _vazio())
        fonte, tipo = evento.get("fonte"), evento.get("tipo")
        if fonte == "auth":
            if tipo == "FAIL":
                b["falhas_login"] += 1
            elif tipo == "OK":
                b["logins_ok"] += 1
            if evento.get("usuario"):
                b["usuarios"].add(evento["usuario"])
        elif fonte == "firewall" and tipo == "BLOCK":
            b["bloqueios_firewall"] += 1
            if evento.get("porta") is not None:
                b["portas"].add(evento["porta"])
        elif fonte == "web":
            b["web_total"] += 1
            if tipo == "FAIL":
                b["web_erros"] += 1

    for alerta in alertas:
        if alerta.get("origem", "regra") == "regra" and alerta.get("ip") in brutos:
            brutos[alerta["ip"]]["alertas_regras"] += 1

    resultado = {}
    for ip, b in brutos.items():
        resultado[ip] = {
            "falhas_login": b["falhas_login"],
            "logins_ok": b["logins_ok"],
            "usuarios_distintos": len(b["usuarios"]),
            "portas_distintas": len(b["portas"]),
            "bloqueios_firewall": b["bloqueios_firewall"],
            "web_erros": b["web_erros"],
            "web_total": b["web_total"],
            "alertas_regras": b["alertas_regras"],
            "em_blacklist": int(ip in blacklist),
            "ip_privado": int(eh_ip_privado(ip)),
        }
    return resultado


def para_vetor(features_ip):
    """dict de features → lista na ordem de FEATURES."""
    return [float(features_ip.get(nome, 0)) for nome in FEATURES]
