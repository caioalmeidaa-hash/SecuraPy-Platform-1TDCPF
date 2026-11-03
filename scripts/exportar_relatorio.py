"""
Gera o "Relatório de exemplo" (entregável 4): JSON exportado pela plataforma
com os dados de teste — mesmo conteúdo de GET /api/relatorio.

Uso:  python -m scripts.exportar_relatorio [saida/relatorio_exemplo.json]
"""

import json
import logging
import os
import sys

from api.servico import ServicoSecuraPy
from db.mongo_repo import conectar

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(destino=None):
    logging.basicConfig(level=logging.WARNING)
    destino = destino or os.path.join(RAIZ, "saida", "relatorio_exemplo.json")
    servico = ServicoSecuraPy(conectar(), repo_usuarios=None, broadcast=False)
    analise = servico.analisar({})  # garante que os dados de teste estão no banco
    relatorio = servico.relatorio_completo()
    relatorio["ultima_analise"] = {k: analise[k] for k in ("eventos_processados", "alertas_gerados",
                                                            "alertas_por_severidade", "ameacas", "deteccoes")}
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2, default=str)
    print(f"[OK] Relatório salvo em {destino} "
          f"({len(relatorio['eventos'])} eventos, {len(relatorio['alertas'])} alertas)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
