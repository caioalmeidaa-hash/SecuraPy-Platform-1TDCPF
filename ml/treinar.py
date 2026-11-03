"""
Treino do classificador de risco por IP (2º sem — Aulas 4 e 12).

Fluxo:
  1. Monta o dataset:
       a) IPs REAIS dos logs (logs/ oficiais + logs/exemplos_reais do 1º sem),
          rotulados pelo núcleo: "ataque" se o detector/blacklist o apontou;
       b) dados SINTÉTICOS (seed fixa → reprodutível) com perfis de tráfego
          normal e de ataque, porque 10 IPs não bastam para treinar nada.
          Há ruído e casos ambíguos de propósito, para as métricas serem honestas.
  2. Compara dois modelos dentro de um Pipeline (StandardScaler + modelo)
     com validação cruzada estratificada (5 folds): precisão, recall, F1.
  3. Escolhe o melhor F1, treina no dataset todo e salva com joblib.
  4. Calcula o SHA-256 do modelo.pkl e grava em modelo.pkl.sha256
     (integridade — mesmo hashlib do 1º semestre). O classificar.py só carrega
     o modelo se o hash conferir, porque carregar pickle adulterado = executar
     código arbitrário.

Uso:  python -m ml.treinar
"""

import hashlib
import json
import logging
import os
import random
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from core.detector import carregar_blacklist
from core.pipeline import CAMINHO_BLACKLIST, RAIZ, analisar_pasta
from ml.features import FEATURES, extrair_features, para_vetor

log = logging.getLogger("securapy.ml.treinar")

PASTA_ML = os.path.dirname(os.path.abspath(__file__))
CAMINHO_MODELO = os.getenv("SECURAPY_MODELO", os.path.join(PASTA_ML, "modelo.pkl"))
CAMINHO_HASH = CAMINHO_MODELO + ".sha256"
CAMINHO_METRICAS = os.path.join(PASTA_ML, "metricas.json")
SEED = 42
ROTULOS = ("normal", "ataque")


def sha256_arquivo(caminho):
    """Hash SHA-256 de um arquivo, lido em blocos (reaproveita hashlib do 1º sem)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(65536), b""):
            h.update(bloco)
    return h.hexdigest()


# ── dataset ──────────────────────────────────────────────────────────────────
def _amostra(rng, perfil):
    """Gera um vetor de features para um perfil de tráfego."""
    r = rng.randint
    p = rng.random
    if perfil == "normal_interno":
        return dict(falhas_login=r(0, 2), logins_ok=r(0, 4), usuarios_distintos=r(0, 2), portas_distintas=0,
                    bloqueios_firewall=r(0, 1), web_erros=r(0, 2), web_total=r(0, 25), alertas_regras=0,
                    em_blacklist=0, ip_privado=1)
    if perfil == "normal_externo":
        return dict(falhas_login=r(0, 2), logins_ok=r(0, 2), usuarios_distintos=r(0, 1), portas_distintas=r(0, 1),
                    bloqueios_firewall=r(0, 2), web_erros=r(0, 3), web_total=r(1, 40),
                    alertas_regras=int(p() < 0.08), em_blacklist=int(p() < 0.03), ip_privado=0)
    if perfil == "usuario_esquecido":  # ruído: muitas falhas, mas é legítimo
        return dict(falhas_login=r(3, 6), logins_ok=r(1, 2), usuarios_distintos=1, portas_distintas=0,
                    bloqueios_firewall=0, web_erros=r(0, 3), web_total=r(0, 10), alertas_regras=int(p() < 0.3),
                    em_blacklist=0, ip_privado=int(p() < 0.6))
    if perfil == "brute_force":
        return dict(falhas_login=r(4, 60), logins_ok=int(p() < 0.1), usuarios_distintos=r(1, 6),
                    portas_distintas=r(0, 2), bloqueios_firewall=r(0, 3), web_erros=r(0, 4), web_total=r(0, 6),
                    alertas_regras=r(2, 40), em_blacklist=int(p() < 0.45), ip_privado=int(p() < 0.05))
    if perfil == "port_scan":
        portas = r(3, 40)
        return dict(falhas_login=r(0, 2), logins_ok=0, usuarios_distintos=r(0, 1), portas_distintas=portas,
                    bloqueios_firewall=portas + r(0, 10), web_erros=r(0, 2), web_total=r(0, 3),
                    alertas_regras=r(1, portas), em_blacklist=int(p() < 0.45), ip_privado=int(p() < 0.05))
    if perfil == "ataque_web":
        total = r(3, 60)
        return dict(falhas_login=r(0, 2), logins_ok=0, usuarios_distintos=0, portas_distintas=r(0, 1),
                    bloqueios_firewall=r(0, 1), web_erros=r(max(1, total // 3), total), web_total=total,
                    alertas_regras=r(1, 10), em_blacklist=int(p() < 0.4), ip_privado=0)
    if perfil == "lento_discreto":  # ruído: ataque "low and slow", difícil de pegar
        return dict(falhas_login=r(1, 4), logins_ok=0, usuarios_distintos=r(1, 3), portas_distintas=r(0, 2),
                    bloqueios_firewall=r(0, 2), web_erros=r(0, 3), web_total=r(0, 5), alertas_regras=r(0, 2),
                    em_blacklist=int(p() < 0.5), ip_privado=0)
    raise ValueError(perfil)


PERFIS = (  # (perfil, rótulo, quantidade)
    ("normal_interno", 0, 220), ("normal_externo", 0, 180), ("usuario_esquecido", 0, 40),
    ("brute_force", 1, 110), ("port_scan", 1, 90), ("ataque_web", 1, 90), ("lento_discreto", 1, 40),
)


def dataset_sintetico(seed=SEED):
    rng = random.Random(seed)
    X, y = [], []
    for perfil, rotulo, quantidade in PERFIS:
        for _ in range(quantidade):
            X.append(para_vetor(_amostra(rng, perfil)))
            y.append(rotulo)
    return X, y


def dataset_dos_logs():
    """IPs reais dos logs, rotulados pelo núcleo do 1º semestre (detector + blacklist)."""
    blacklist = carregar_blacklist(CAMINHO_BLACKLIST)
    X, y = [], []
    for pasta in (os.path.join(RAIZ, "logs"), os.path.join(RAIZ, "logs", "exemplos_reais")):
        if not os.path.isdir(pasta):
            continue
        resultado = analisar_pasta(pasta, blacklist=blacklist)
        suspeitos = {a["ip"] for a in resultado["ameacas"]}
        feats = extrair_features(resultado["eventos"], resultado["alertas"], blacklist)
        for ip, f in feats.items():
            X.append(para_vetor(f))
            y.append(int(ip in suspeitos or f["alertas_regras"] >= 2))
    return X, y


def montar_dataset():
    Xs, ys = dataset_sintetico()
    Xr, yr = dataset_dos_logs()
    return np.array(Xs + Xr, dtype=float), np.array(ys + yr, dtype=int), len(Xr)


# ── modelos ──────────────────────────────────────────────────────────────────
def candidatos():
    return {
        "regressao_logistica": Pipeline([
            ("scaler", StandardScaler()),
            ("modelo", LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)),
        ]),
        "random_forest": Pipeline([
            ("scaler", StandardScaler()),
            ("modelo", RandomForestClassifier(n_estimators=200, max_depth=6, min_samples_leaf=2,
                                              class_weight="balanced", random_state=SEED)),
        ]),
    }


def avaliar(X, y):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    resultados = {}
    for nome, pipe in candidatos().items():
        cv_res = cross_validate(pipe, X, y, cv=cv, scoring=("precision", "recall", "f1", "accuracy"))
        resultados[nome] = {
            m: {"media": round(float(np.mean(cv_res[f"test_{m}"])), 4),
                "desvio": round(float(np.std(cv_res[f"test_{m}"])), 4)}
            for m in ("precision", "recall", "f1", "accuracy")
        }
    return resultados


def treinar(caminho_modelo=CAMINHO_MODELO, verbose=True):
    X, y, n_reais = montar_dataset()
    validacao_cruzada = avaliar(X, y)
    melhor = max(validacao_cruzada, key=lambda n: validacao_cruzada[n]["f1"]["media"])

    # Relatório em holdout (20%) só para exibir matriz de confusão e report por classe
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    pipe_holdout = candidatos()[melhor].fit(X_tr, y_tr)
    y_pred = pipe_holdout.predict(X_te)
    relatorio = classification_report(y_te, y_pred, target_names=ROTULOS, digits=3)
    matriz = confusion_matrix(y_te, y_pred).tolist()

    # Modelo final: treinado com tudo
    final = candidatos()[melhor].fit(X, y)
    pacote = {
        "pipeline": final,
        "features": FEATURES,
        "rotulos": ROTULOS,
        "algoritmo": melhor,
        "treinado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    joblib.dump(pacote, caminho_modelo)
    hash_modelo = sha256_arquivo(caminho_modelo)
    with open(caminho_modelo + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{hash_modelo}  {os.path.basename(caminho_modelo)}\n")

    importancias = None
    if hasattr(final.named_steps["modelo"], "feature_importances_"):
        importancias = {n: round(float(v), 4) for n, v in
                        zip(FEATURES, final.named_steps["modelo"].feature_importances_)}

    metricas = {
        "algoritmo_escolhido": melhor,
        "amostras": {"total": int(len(y)), "ataque": int(y.sum()), "normal": int(len(y) - y.sum()),
                     "ips_reais_dos_logs": n_reais},
        "validacao_cruzada_5_folds": validacao_cruzada,
        "holdout_20pct": {"relatorio": relatorio, "matriz_confusao[[TN,FP],[FN,TP]]": matriz},
        "importancia_features": importancias,
        "sha256_modelo": hash_modelo,
        "treinado_em": pacote["treinado_em"],
    }
    with open(CAMINHO_METRICAS, "w", encoding="utf-8") as f:
        json.dump(metricas, f, ensure_ascii=False, indent=2)

    if verbose:
        print("=== Treino do classificador de risco — SecuraPy ===")
        print(f"Amostras: {metricas['amostras']}")
        print("\nValidação cruzada estratificada (5 folds):")
        for nome, m in validacao_cruzada.items():
            print(f"  {nome:20s} precisão={m['precision']['media']:.3f}  recall={m['recall']['media']:.3f}"
                  f"  F1={m['f1']['media']:.3f} (±{m['f1']['desvio']:.3f})")
        print(f"\nEscolhido: {melhor}\n\nHoldout 20%:\n{relatorio}")
        print(f"Matriz de confusão [[TN, FP], [FN, TP]]: {matriz}")
        print(f"\nModelo salvo em {caminho_modelo}\nSHA-256: {hash_modelo}")
    return metricas


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    treinar()
