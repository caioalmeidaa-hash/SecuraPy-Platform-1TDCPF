"""
BÔNUS — Detecção de anomalias com Isolation Forest (2º sem — Aula 12).

As regras e o classificador só reconhecem o que já conhecem. O Isolation
Forest aprende como é o tráfego NORMAL (baseline sintética de perfis
legítimos) e marca como anômalo qualquer IP que fuja desse padrão — mesmo
que não bata com nenhuma regra.
"""

import random

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from ml.features import extrair_features, para_vetor
from ml.treinar import SEED, _amostra

_modelo = None


def _baseline_normal(n=500, seed=SEED):
    rng = random.Random(seed)
    perfis = ("normal_interno", "normal_externo")
    return [para_vetor(_amostra(rng, perfis[i % 2])) for i in range(n)]


def modelo_anomalias():
    global _modelo
    if _modelo is None:
        _modelo = Pipeline([
            ("scaler", StandardScaler()),
            ("iforest", IsolationForest(n_estimators=200, contamination=0.02, random_state=SEED)),
        ]).fit(_baseline_normal())
    return _modelo


def detectar_anomalias(eventos, alertas=(), blacklist=frozenset()):
    """
    Retorna {ip: {"anomalo": bool, "score_anomalia": float}}.
    score_anomalia > 0 = mais estranho que o normal (quanto maior, mais anômalo).
    """
    feats = extrair_features(eventos, alertas, blacklist)
    if not feats:
        return {}
    ips = list(feats)
    vetores = [para_vetor(feats[ip]) for ip in ips]
    modelo = modelo_anomalias()
    rotulos = modelo.predict(vetores)
    scores = -modelo.decision_function(vetores)
    return {ip: {"anomalo": bool(r == -1), "score_anomalia": round(float(s), 4)}
            for ip, r, s in zip(ips, rotulos, scores)}
