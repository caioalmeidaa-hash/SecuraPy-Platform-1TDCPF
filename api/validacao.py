"""
Validação de entrada da API — tudo que vem do cliente é não confiável.
Cada função devolve o valor normalizado ou levanta ErroValidacao (→ HTTP 400).
"""

import ipaddress
import re
from datetime import datetime

FONTES = frozenset({"auth", "firewall", "web", "correlacao", "manual"})
TIPOS = frozenset({"FAIL", "OK", "BLOCK", "ALLOW", "REQUEST", "PRIVILEGE_ESCALATION"})
SEVERIDADES = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
_RE_ID_ALERTA = re.compile(r"^[a-f0-9]{64}$")
_RE_REGRA_ID = re.compile(r"^[A-Z0-9_-]{1,20}$")
_ACENTOS = str.maketrans("ÍÉÁÚÓíéáúó", "IEAUOieauo")


class ErroValidacao(ValueError):
    pass


def validar_ip(valor):
    try:
        return str(ipaddress.ip_address(str(valor).strip()))
    except ValueError:
        raise ErroValidacao("IP inválido") from None


def validar_id_alerta(valor):
    if not isinstance(valor, str) or not _RE_ID_ALERTA.match(valor):
        raise ErroValidacao("ID de alerta inválido")
    return valor


def validar_severidade(valor):
    sev = str(valor).strip().upper().translate(_ACENTOS)
    if sev not in SEVERIDADES:
        raise ErroValidacao(f"Severidade inválida (use: {', '.join(s.lower() for s in SEVERIDADES)})")
    return sev


def validar_inteiro(valor, nome, minimo, maximo, padrao):
    if valor in (None, ""):
        return padrao
    try:
        numero = int(valor)
    except (TypeError, ValueError):
        raise ErroValidacao(f"'{nome}' deve ser inteiro") from None
    if not minimo <= numero <= maximo:
        raise ErroValidacao(f"'{nome}' deve estar entre {minimo} e {maximo}")
    return numero


def validar_data(valor, nome):
    if not valor:
        return None
    try:
        return datetime.fromisoformat(str(valor))
    except ValueError:
        raise ErroValidacao(f"'{nome}' deve ser data ISO 8601 (ex.: 2025-02-20T08:15:00)") from None


def validar_texto(valor, nome, maximo, obrigatorio=True):
    if valor is None or (isinstance(valor, str) and not valor.strip()):
        if obrigatorio:
            raise ErroValidacao(f"'{nome}' é obrigatório")
        return None
    if not isinstance(valor, str):
        raise ErroValidacao(f"'{nome}' deve ser texto")
    valor = valor.strip()
    if len(valor) > maximo:
        raise ErroValidacao(f"'{nome}' excede {maximo} caracteres")
    return valor


def paginacao(args):
    return (validar_inteiro(args.get("pagina"), "pagina", 1, 100000, 1),
            validar_inteiro(args.get("tamanho"), "tamanho", 1, 100, 20))


def filtros_eventos(args):
    filtros = {}
    if args.get("fonte"):
        if args["fonte"] not in FONTES:
            raise ErroValidacao("Fonte inválida (auth, firewall ou web)")
        filtros["fonte"] = args["fonte"]
    if args.get("tipo"):
        tipo = args["tipo"].upper()
        if tipo not in TIPOS:
            raise ErroValidacao("Tipo inválido")
        filtros["tipo"] = tipo
    if args.get("ip"):
        filtros["ip"] = validar_ip(args["ip"])
    filtros["inicio"] = validar_data(args.get("inicio"), "inicio")
    filtros["fim"] = validar_data(args.get("fim"), "fim")
    return filtros


def filtros_alertas(args):
    filtros = {}
    if args.get("severidade"):
        filtros["severidade"] = validar_severidade(args["severidade"])
    if args.get("ip"):
        filtros["ip"] = validar_ip(args["ip"])
    if args.get("regra_id"):
        if not _RE_REGRA_ID.match(args["regra_id"]):
            raise ErroValidacao("regra_id inválido")
        filtros["regra_id"] = args["regra_id"]
    return filtros


def corpo_alerta(dados):
    """Valida o JSON de POST /api/alertas. Só campos da lista branca são aceitos."""
    if not isinstance(dados, dict):
        raise ErroValidacao("Corpo deve ser um objeto JSON")
    regra_id = validar_texto(dados.get("regra_id"), "regra_id", 20, obrigatorio=False) or "MANUAL"
    if not _RE_REGRA_ID.match(regra_id):
        raise ErroValidacao("regra_id inválido")
    return {
        "ip": validar_ip(dados.get("ip", "")),
        "severidade": validar_severidade(dados.get("severidade", "")),
        "regra_id": regra_id,
        "regra_nome": validar_texto(dados.get("regra_nome"), "regra_nome", 100),
        "descricao": validar_texto(dados.get("descricao"), "descricao", 500),
        "fonte": "manual",
        "origem": "manual",
    }
