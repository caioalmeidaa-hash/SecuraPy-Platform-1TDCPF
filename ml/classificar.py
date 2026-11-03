"""
Classificação/priorização de risco por IP (2º sem — Aulas 4 e 12).

  - Verifica o SHA-256 do modelo.pkl ANTES de carregá-lo. joblib usa pickle,
    e desserializar um pickle adulterado executa código arbitrário — então
    hash divergente = não carrega, registra alerta CRÍTICO (C4).
  - pontuar() devolve, para cada IP, um score 0–100 (probabilidade de ataque),
    o rótulo ("ataque"/"normal") e um nível de risco para ordenar alertas.

Uso rápido:  python -m ml.classificar 185.220.101.1 192.168.1.10
"""

import hmac
import logging
import os
import sys

import joblib

from ml.features import FEATURES, extrair_features, para_vetor
from ml.treinar import CAMINHO_MODELO, sha256_arquivo

log = logging.getLogger("securapy.ml.classificar")

LIMIAR_ATAQUE = 0.5


class ModeloIntegridadeError(Exception):
    """O hash do modelo não confere com o registrado (possível adulteração)."""


def hash_registrado(caminho_hash):
    with open(caminho_hash, encoding="utf-8") as f:
        return f.read().split()[0].strip().lower()


def verificar_integridade(caminho_modelo=CAMINHO_MODELO, caminho_hash=None):
    """True se o SHA-256 atual do arquivo bate com o registrado no treino."""
    caminho_hash = caminho_hash or caminho_modelo + ".sha256"
    try:
        esperado = hash_registrado(caminho_hash)
        atual = sha256_arquivo(caminho_modelo)
    except (OSError, IndexError):
        return False
    return hmac.compare_digest(esperado, atual)


def nivel_risco(score):
    """Score 0–100 → nível textual (tupla de faixas, do maior para o menor)."""
    for limite, nivel in ((85, "CRITICO"), (65, "ALTO"), (40, "MEDIO"), (0, "BAIXO")):
        if score >= limite:
            return nivel
    return "BAIXO"


class ClassificadorRisco:
    def __init__(self, caminho_modelo=CAMINHO_MODELO):
        self.caminho_modelo = caminho_modelo
        self._pacote = None

    def carregar(self):
        if self._pacote is not None:
            return self._pacote
        if not os.path.exists(self.caminho_modelo):
            raise FileNotFoundError("Modelo não encontrado — rode: python -m ml.treinar")
        if not verificar_integridade(self.caminho_modelo):
            log.critical("[ALERTA] Integridade do modelo FALHOU: hash não confere (%s)", self.caminho_modelo)
            raise ModeloIntegridadeError("Hash do modelo não confere — carregamento bloqueado")
        pacote = joblib.load(self.caminho_modelo)
        if tuple(pacote.get("features", ())) != FEATURES:
            raise ModeloIntegridadeError("Modelo treinado com outro conjunto de features — re-treine")
        self._pacote = pacote
        return pacote

    @property
    def disponivel(self):
        try:
            self.carregar()
            return True
        except (FileNotFoundError, ModeloIntegridadeError):
            return False

    def pontuar_features(self, features_por_ip):
        """{ip: features} → {ip: {score, rotulo, nivel, features}}"""
        if not features_por_ip:
            return {}
        pacote = self.carregar()
        ips = list(features_por_ip)
        probabilidades = pacote["pipeline"].predict_proba([para_vetor(features_por_ip[ip]) for ip in ips])[:, 1]
        resultado = {}
        for ip, prob in zip(ips, probabilidades):
            score = round(float(prob) * 100, 1)
            resultado[ip] = {
                "score": score,
                "rotulo": "ataque" if prob >= LIMIAR_ATAQUE else "normal",
                "nivel": nivel_risco(score),
                "features": features_por_ip[ip],
                "modelo": pacote["algoritmo"],
            }
        return resultado

    def pontuar(self, eventos, alertas=(), blacklist=frozenset()):
        return self.pontuar_features(extrair_features(eventos, alertas, blacklist))


def priorizar_alertas(alertas, scores):
    """Anexa score_risco a cada alerta e ordena: maior risco ML primeiro, depois severidade."""
    peso = {"CRITICA": 5, "ALTA": 4, "MEDIA": 3, "BAIXA": 2, "INFO": 1}
    saida = []
    for alerta in alertas:
        info = scores.get(alerta.get("ip"), {})
        saida.append(dict(alerta, score_risco=info.get("score"), rotulo_ml=info.get("rotulo")))
    saida.sort(key=lambda a: (a["score_risco"] or 0, peso.get(a.get("severidade"), 0)), reverse=True)
    return saida


if __name__ == "__main__":
    from core.detector import carregar_blacklist
    from core.pipeline import CAMINHO_BLACKLIST, analisar_pasta

    logging.basicConfig(level=logging.WARNING)
    print("Integridade do modelo:", "OK" if verificar_integridade() else "FALHOU")
    bl = carregar_blacklist(CAMINHO_BLACKLIST)
    r = analisar_pasta(blacklist=bl)
    scores = ClassificadorRisco().pontuar(r["eventos"], r["alertas"], bl)
    alvo = sys.argv[1:] or sorted(scores, key=lambda ip: -scores[ip]["score"])
    for ip in alvo:
        s = scores.get(ip)
        print(f"{ip:18s} " + (f"score={s['score']:5.1f}  rótulo={s['rotulo']:7s} nível={s['nivel']}" if s else "sem eventos"))
