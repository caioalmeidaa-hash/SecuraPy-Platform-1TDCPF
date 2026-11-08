"""
Nota de saúde da segurança (0 a 100) — para quem não entende de segurança.

Começa em 100 e cada problema encontrado nos registros tira pontos. A nota é
TRANSPARENTE: todo desconto vem com o motivo, e as ações recomendadas saem do
manual de correções (ia/diagnostico.py) para os atacantes mais perigosos.
É uma conta simples e auditável — não é IA —, de propósito: um leigo precisa
confiar no número.
"""

from ia.diagnostico import coletar_evidencias, manual_de_correcoes
from ia.indicios import avaliar_ip

FAIXAS = ((80, "Boa", "boa"), (60, "Atenção", "atencao"), (40, "Em risco", "risco"), (0, "Crítica", "critica"))
TITULOS = {
    "R006": "Corrigir as consultas ao banco de dados do site",
    "R003": "Proteger o download de arquivos do site",
    "R004": "Limpar o texto que o site mostra na tela",
    "LOGIN": "Desligar o login por senha no acesso remoto (SSH)",
    "PORTAS": "Fechar as portas que não precisam ficar abertas",
    "C003": "Bloquear endereços da lista negra",
    "R005": "Bloquear robôs de varredura",
}


def calcular(repo, limite_ips=5):
    totais = repo.totais()
    if not totais.get("alertas"):
        return {"nota": 100, "faixa": "Boa", "classe": "boa",
                "descontos": [], "resumo": "Nenhum ataque detectado nos registros até agora.",
                "acoes": []}

    descontos = []
    scores = [s for s in repo.listar_scores(limite_ips) if s.get("ip")]
    perigosos = [s for s in scores if (s.get("score") or 0) >= 65]
    criticos = repo.contagem_por_severidade().get("CRITICA", 0)

    if criticos:
        descontos.append({"pontos": min(20, 2 * criticos),
                          "motivo": f"{criticos} alerta(s) de gravidade CRÍTICA registrados."})
    if perigosos:
        descontos.append({"pontos": min(15, 5 * len(perigosos)),
                          "motivo": f"{len(perigosos)} endereço(s) com risco alto (65+ de 100) atacando: "
                                    + ", ".join(s["ip"] for s in perigosos) + "."})

    acoes, vistos = [], set()
    for s in scores:
        ip = s["ip"]
        alertas, eventos = repo.alertas_do_ip(ip), repo.eventos_do_ip(ip)
        ind = avaliar_ip(alertas, eventos)
        for frase in ind["indicios"]:
            if frase.startswith("ATENÇÃO"):
                descontos.append({"pontos": 61, "motivo": f"Possível invasão por {ip}: login aceito depois de senhas "
                                                          "erradas. Com suspeita de invasão a nota não passa de 39 "
                                                          "até alguém verificar o servidor."})
                if "invasao" not in vistos:
                    vistos.add("invasao")
                    acoes.insert(0, {"titulo": "Trocar as senhas e verificar o servidor agora",
                                     "como": f"Houve login aceito do endereço {ip} depois de várias senhas erradas. "
                                             "Troque as senhas das contas atacadas e confira o que foi feito no servidor."})
            elif "NÃO dá para garantir" in frase:
                descontos.append({"pontos": 10, "motivo": f"Ataques de {ip} ao site receberam resposta normal "
                                                          "(não dá para garantir que foram barrados)."})
            elif "ERRO INTERNO" in frase:
                descontos.append({"pontos": 10, "motivo": f"Ataques de {ip} causaram erro interno no servidor."})
            elif "PERMITIDAS" in frase:
                descontos.append({"pontos": 10, "motivo": f"O firewall deixou passar conexões de {ip}."})
        evidencias = coletar_evidencias(alertas, eventos, ip)
        for g, item in zip(evidencias, manual_de_correcoes(evidencias, ip)):
            if g["regra"] not in vistos and g["regra"] in TITULOS:
                vistos.add(g["regra"])
                acoes.append({"titulo": TITULOS[g["regra"]], "como": f"{item['onde']}: {item['correcao']}"})

    nota = max(0, 100 - sum(d["pontos"] for d in descontos))
    faixa, classe = next((f, c) for limite, f, c in FAIXAS if nota >= limite)
    return {"nota": nota, "faixa": faixa, "classe": classe, "descontos": descontos,
            "resumo": f"Sua empresa está com nota {nota} de 100 ({faixa.lower()}).",
            "acoes": acoes[:3]}
