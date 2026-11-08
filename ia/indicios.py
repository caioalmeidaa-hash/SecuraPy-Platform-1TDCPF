"""
Indícios de resultado — "o ataque deu certo ou não?", calculado a partir dos LOGS.

A IA não pode afirmar que um ataque falhou (ou funcionou) só porque "parece".
Este módulo olha o que os logs realmente mostram para um IP e devolve frases
com o MOTIVO de cada conclusão. Elas vão para o Gemini (que só pode concluir
a partir delas) e aparecem na tela, para o analista conferir.

Limite honesto: o SIEM só enxerga os logs. Ele não vê se dados saíram da
empresa — então nunca afirmamos que "os dados estão seguros".
"""

WEB_ATAQUES = {"R003", "R004", "R005", "R006"}
LIMITE = ("Limite: o SecuraPy só enxerga os registros (logs); ele não consegue confirmar se algum dado "
          "saiu da empresa. Para isso é preciso verificar o servidor atacado.")


def avaliar_ip(alertas, eventos):
    """
    Retorna {"possivel_sucesso": bool, "indicios": [frases com o motivo]}.
    possivel_sucesso = há pelo menos um sinal de que algum ataque pode ter funcionado.
    """
    if not alertas:
        return {"possivel_sucesso": False,
                "indicios": ["Nenhum alerta de ataque para este endereço: comportamento normal nos registros.", LIMITE]}
    linhas_de_ataque = {a.get("evento_original") for a in alertas if a.get("regra_id") in WEB_ATAQUES}
    falhas_login = sum(1 for e in eventos if e.get("fonte") == "auth" and e.get("tipo") == "FAIL")
    logins_aceitos = sum(1 for e in eventos if e.get("fonte") == "auth" and e.get("tipo") == "OK")
    bloqueios = sum(1 for e in eventos if e.get("fonte") == "firewall" and e.get("tipo") == "BLOCK")
    permitidos = sum(1 for e in eventos if e.get("fonte") == "firewall" and e.get("tipo") == "ALLOW")
    status = [str(e.get("status", "")) for e in eventos
              if e.get("fonte") == "web" and e.get("linha_original") in linhas_de_ataque]

    indicios, suspeito = [], False
    if logins_aceitos and falhas_login:
        suspeito = True
        indicios.append(f"ATENÇÃO: {logins_aceitos} login(s) foram ACEITOS a partir deste endereço depois das "
                        f"tentativas — é possível que o atacante tenha conseguido entrar.")
    elif falhas_login:
        indicios.append(f"Nenhum login foi aceito: as {falhas_login} tentativas de senha falharam "
                        f"(todas registradas como 'Failed password').")
    if bloqueios and not permitidos:
        indicios.append(f"As {bloqueios} tentativas de conexão em portas foram BLOQUEADAS pelo firewall.")
    elif permitidos and bloqueios:
        suspeito = True
        indicios.append(f"{permitidos} conexão(ões) deste endereço foram PERMITIDAS pelo firewall "
                        f"(e {bloqueios} bloqueadas) — verificar o que ele acessou.")
    if status:
        ok = sum(1 for s in status if s.startswith("2") or s.startswith("3"))
        negados = sum(1 for s in status if s in ("401", "403"))
        inexistentes = sum(1 for s in status if s == "404")
        erros = sum(1 for s in status if s.startswith("5"))
        if ok:
            suspeito = True
            indicios.append(f"{ok} de {len(status)} pedidos maliciosos ao site receberam resposta normal "
                            f"(código 2xx/3xx): o site respondeu, então NÃO dá para garantir que foram barrados.")
        if erros:
            suspeito = True
            indicios.append(f"{erros} pedido(s) causaram ERRO INTERNO no servidor (código 5xx): sinal de que o "
                            f"ataque mexeu em algo — precisa investigar.")
        if negados:
            indicios.append(f"{negados} pedido(s) foram RECUSADOS pelo site (código 401/403).")
        if inexistentes:
            indicios.append(f"{inexistentes} pedido(s) procuraram páginas que NÃO EXISTEM (código 404).")
    indicios.append(LIMITE)
    return {"possivel_sucesso": suspeito, "indicios": indicios}
