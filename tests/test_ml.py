"""Módulo C — Machine Learning (cenários C1–C4 + bônus Isolation Forest)."""

import json
import shutil

import pytest

from ml.anomalias import detectar_anomalias
from ml.classificar import ClassificadorRisco, ModeloIntegridadeError, priorizar_alertas, verificar_integridade
from ml.treinar import CAMINHO_METRICAS, CAMINHO_MODELO
from tests.conftest import BLACKLIST


@pytest.fixture(scope="module")
def scores(analise):
    return ClassificadorRisco().pontuar(analise["eventos"], analise["alertas"], BLACKLIST)


def test_c1_metricas_registradas():
    with open(CAMINHO_METRICAS, encoding="utf-8") as f:
        metricas = json.load(f)
    for modelo in metricas["validacao_cruzada_5_folds"].values():
        assert {"precision", "recall", "f1"} <= modelo.keys()
    escolhido = metricas["validacao_cruzada_5_folds"][metricas["algoritmo_escolhido"]]
    assert escolhido["f1"]["media"] > 0.8


def test_c2_185_e_ataque_com_risco_alto(scores):
    assert scores["185.220.101.1"]["rotulo"] == "ataque"
    assert scores["185.220.101.1"]["nivel"] in ("ALTO", "CRITICO")


def test_c3_192_168_1_10_e_normal(scores):
    assert scores["192.168.1.10"]["rotulo"] == "normal"


def test_c4_integridade_ok_e_adulteracao_detectada(tmp_path):
    assert verificar_integridade(CAMINHO_MODELO)
    copia = tmp_path / "modelo.pkl"
    shutil.copy(CAMINHO_MODELO, copia)
    shutil.copy(CAMINHO_MODELO + ".sha256", str(copia) + ".sha256")
    assert ClassificadorRisco(str(copia)).disponivel
    with open(copia, "ab") as f:
        f.write(b"\x00adulterado")
    assert not verificar_integridade(str(copia))
    with pytest.raises(ModeloIntegridadeError):
        ClassificadorRisco(str(copia)).carregar()


def test_priorizacao_ordena_por_risco(analise, scores):
    ordenados = priorizar_alertas(analise["alertas"], scores)
    riscos = [a["score_risco"] or 0 for a in ordenados]
    assert riscos == sorted(riscos, reverse=True)


def test_bonus_isolation_forest(analise):
    anomalias = detectar_anomalias(analise["eventos"], analise["alertas"], BLACKLIST)
    assert anomalias["185.220.101.1"]["anomalo"] is True
    assert anomalias["192.168.1.10"]["anomalo"] is False
