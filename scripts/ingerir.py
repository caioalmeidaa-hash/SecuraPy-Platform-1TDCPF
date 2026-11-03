"""
Migração / ingestão inicial (Módulo B, requisito 3).

Lê os logs pelo NÚCLEO do 1º semestre, aplica regras + detector + ML e grava
eventos, alertas e scores no MongoDB. Pode ser executado várias vezes:
a ingestão é idempotente (eventos repetidos não duplicam).

Uso:
    python -m scripts.ingerir                  # pasta logs/
    python -m scripts.ingerir logs/exemplos_reais
"""

import logging
import os
import sys

from api.servico import ServicoSecuraPy
from core.pipeline import PASTA_LOGS
from db import RepositorioIndisponivel
from db.mongo_repo import conectar


def main(pasta=None):
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    repo = conectar()
    try:
        repo.criar_indices()
    except RepositorioIndisponivel:
        print("[ERRO] MongoDB indisponível. Verifique MONGO_URI ou suba o docker compose.")
        return 1

    servico = ServicoSecuraPy(repo, repo_usuarios=None, broadcast=False)
    pasta = os.path.abspath(pasta or PASTA_LOGS)
    raiz_logs = os.path.abspath(PASTA_LOGS)
    corpo = {} if pasta == raiz_logs else {"pasta": os.path.relpath(pasta, raiz_logs)}
    resultado = servico.analisar(corpo)

    p = resultado["persistencia"]
    print(f"Eventos processados : {resultado['eventos_processados']}")
    print(f"Eventos gravados    : {p['eventos']['inseridos']} novos, {p['eventos']['duplicados']} já existiam")
    print(f"Alertas gravados    : {p['alertas']['inseridos']} novos, {p['alertas']['duplicados']} já existiam")
    print(f"Por fonte (MongoDB) : {repo.contagem_por_fonte()}")
    print("Top 5 IPs (agregação):")
    for item in repo.top_ips(5):
        print(f"   {item['ip']:18s} {item['eventos']:3d} eventos  fontes={','.join(item['fontes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else None))
