"""
Serviço de aplicação — orquestra as camadas (núcleo → ML → banco → alertas → LLM).

É o "main.py" da plataforma: a API REST e o dashboard web chamam este
serviço, que por sua vez reaproveita o núcleo do 1º semestre sem conhecer HTTP.
"""

import logging
import os
from datetime import datetime

from alertas import servidor_alertas
from core.coletor import MAPA_ARQUIVOS, carregar_log, carregar_todos_os_logs, parsear_linhas
from core.detector import carregar_blacklist
from core.enriquecimento import consultar_ip
from core.pipeline import CAMINHO_BLACKLIST, CAMINHO_REGRAS, PASTA_LOGS, analisar_eventos
from core.regras import carregar_regras
from ia.assistente import classificar_evento
from ml.anomalias import detectar_anomalias
from ml.classificar import ClassificadorRisco, ModeloIntegridadeError, priorizar_alertas, verificar_integridade
from ml.features import extrair_features

log = logging.getLogger("securapy.servico")

MAX_EVENTOS_LOTE = 5000
SEVERIDADES_TEMPO_REAL = frozenset({"CRITICA", "ALTA"})


class ErroEntrada(ValueError):
    """Entrada de análise inválida (vira HTTP 400)."""


class ServicoSecuraPy:
    def __init__(self, repo_eventos, repo_usuarios, classificador=None, pasta_logs=PASTA_LOGS,
                 broadcast=True):
        self.repo = repo_eventos
        self.usuarios = repo_usuarios
        self.classificador = classificador or ClassificadorRisco()
        self.pasta_logs = os.path.realpath(pasta_logs)
        self.broadcast = broadcast
        self.cache_geo = {}

    # ── entrada de dados ────────────────────────────────────────────────────
    def _caminho_seguro(self, relativo):
        """Resolve um caminho DENTRO da pasta de logs (bloqueia ../../etc/passwd)."""
        if not isinstance(relativo, str) or not relativo.strip() or "\x00" in relativo:
            raise ErroEntrada("Caminho inválido")
        alvo = os.path.realpath(os.path.join(self.pasta_logs, relativo.strip()))
        if os.path.commonpath([alvo, self.pasta_logs]) != self.pasta_logs:
            raise ErroEntrada("Caminho fora da pasta de logs permitida")
        return alvo

    def eventos_da_requisicao(self, corpo):
        """
        Aceita três formatos no POST /api/analisar:
          {}                                     → pasta de logs padrão
          {"pasta": "exemplos_reais"}            → subpasta dentro de logs/
          {"caminho": "auth.log", "fonte": "auth"}  → um arquivo (fonte deduzida pelo nome se omitida)
          {"eventos": [{"fonte": "web", "linha": "..."}]}  → lote de linhas cruas
        """
        corpo = corpo or {}
        if not isinstance(corpo, dict):
            raise ErroEntrada("Corpo deve ser um objeto JSON")

        if "eventos" in corpo:
            lote = corpo["eventos"]
            if not isinstance(lote, list) or not lote:
                raise ErroEntrada("'eventos' deve ser uma lista não vazia")
            if len(lote) > MAX_EVENTOS_LOTE:
                raise ErroEntrada(f"Máximo de {MAX_EVENTOS_LOTE} eventos por lote")
            eventos, ignoradas = [], 0
            for item in lote:
                if not isinstance(item, dict) or item.get("fonte") not in MAPA_ARQUIVOS.values() \
                        or not isinstance(item.get("linha"), str):
                    raise ErroEntrada("Cada evento deve ter 'fonte' (auth|firewall|web) e 'linha' (texto)")
                parseados, ign = parsear_linhas([item["linha"][:4000]], item["fonte"])
                eventos += parseados
                ignoradas += ign
            return eventos, {"origem": "lote", "linhas_ignoradas": ignoradas}

        if "caminho" in corpo:
            caminho = self._caminho_seguro(corpo["caminho"])
            fonte = corpo.get("fonte") or MAPA_ARQUIVOS.get(os.path.basename(caminho))
            if fonte not in MAPA_ARQUIVOS.values():
                raise ErroEntrada("Informe 'fonte' (auth|firewall|web)")
            if not os.path.isfile(caminho):
                raise ErroEntrada("Arquivo de log não encontrado")
            return carregar_log(caminho, fonte), {"origem": os.path.relpath(caminho, self.pasta_logs)}

        pasta = self._caminho_seguro(corpo.get("pasta", ".")) if corpo.get("pasta") else self.pasta_logs
        if not os.path.isdir(pasta):
            raise ErroEntrada("Pasta de logs não encontrada")
        return carregar_todos_os_logs(pasta), {"origem": os.path.relpath(pasta, self.pasta_logs)}

    # ── análise ponta a ponta ───────────────────────────────────────────────
    def pontuar(self, eventos, alertas, blacklist):
        """Score de ML + anomalias por IP. Se o modelo falhar, a análise segue sem score."""
        try:
            scores = self.classificador.pontuar(eventos, alertas, blacklist)
        except (FileNotFoundError, ModeloIntegridadeError) as e:
            log.error("ML indisponível: %s", e)
            scores = {}
        anomalias = detectar_anomalias(eventos, alertas, blacklist)
        if anomalias and not scores:
            features = extrair_features(eventos, alertas, blacklist)
            scores = {ip: {"features": features[ip]} for ip in anomalias}
        for ip, info in anomalias.items():
            scores.setdefault(ip, {}).update(info)
        return scores

    def analisar(self, corpo=None):
        eventos, meta = self.eventos_da_requisicao(corpo)
        regras = carregar_regras(CAMINHO_REGRAS)
        blacklist = carregar_blacklist(CAMINHO_BLACKLIST)
        resultado = analisar_eventos(eventos, regras, blacklist)

        scores = self.pontuar(eventos, resultado["alertas"], blacklist)
        alertas = priorizar_alertas(resultado["alertas"], scores)

        gravacao_eventos = self.repo.salvar_eventos(eventos)
        gravacao_alertas = self.repo.salvar_alertas(alertas)
        self.repo.salvar_scores({ip: dict(s, atualizado_em=datetime.now().isoformat(timespec="seconds"))
                                 for ip, s in scores.items()})

        enviados = self._transmitir(alertas, resultado["ameacas"], scores) if self.broadcast else 0

        por_severidade = {}
        for a in alertas:
            por_severidade[a["severidade"]] = por_severidade.get(a["severidade"], 0) + 1
        ameacas = [dict(a, score_ml=scores.get(a["ip"], {}).get("score"),
                        rotulo_ml=scores.get(a["ip"], {}).get("rotulo"),
                        anomalo=scores.get(a["ip"], {}).get("anomalo"))
                   for a in resultado["ameacas"]]
        return {
            **meta,
            "eventos_processados": len(eventos),
            "alertas_gerados": len(alertas),
            "persistencia": {"eventos": gravacao_eventos, "alertas": gravacao_alertas},
            "alertas_por_severidade": por_severidade,
            "ameacas": ameacas,
            "deteccoes": resultado["deteccoes"],
            "ml": {"modelo_ok": bool(scores) and any("score" in s for s in scores.values()),
                   "ips_pontuados": len(scores)},
            "alertas_tempo_real_enviados": enviados,
        }

    def _transmitir(self, alertas, ameacas, scores):
        """Envia alertas CRITICA/ALTA (e o resumo das ameaças) aos consoles TCP conectados."""
        enviados = 0
        for alerta in alertas:
            if alerta["severidade"] in SEVERIDADES_TEMPO_REAL:
                texto = dict(alerta)
                if alerta.get("score_risco") is not None:
                    texto["descricao"] = f"{alerta['descricao']} | risco ML {alerta['score_risco']}"
                servidor_alertas.broadcast_alerta(texto)
                enviados += 1
        for ameaca in ameacas:
            if ameaca["severidade"] == "CRITICA":
                score = scores.get(ameaca["ip"], {}).get("score")
                servidor_alertas.broadcast_alerta(
                    f"[CRITICA] AMEAÇA CONSOLIDADA {ameaca['ip']} — {'; '.join(ameaca['motivos'])}"
                    + (f" — risco ML {score}" if score is not None else ""))
                enviados += 1
        return enviados

    # ── consultas ───────────────────────────────────────────────────────────
    def detalhes_ip(self, ip, com_llm=True):
        eventos = self.repo.eventos_do_ip(ip)
        alertas = self.repo.alertas_do_ip(ip)
        if not eventos and not alertas:
            return None
        score = self.repo.obter_score(ip)
        explicacao = None
        if com_llm:
            alvo = alertas[0] if alertas else eventos[-1]
            explicacao = classificar_evento(alvo)
        return {
            "ip": ip,
            "geo": consultar_ip(ip, self.cache_geo),
            "score_ml": score,
            "explicacao_llm": explicacao,
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "eventos": eventos,
            "alertas": alertas,
        }

    def criar_alerta_manual(self, alerta, autor):
        agora = datetime.now()
        alerta = dict(alerta, timestamp=agora.strftime("%Y-%m-%d %H:%M:%S"),
                      timestamp_iso=agora.isoformat(timespec="seconds"), criado_por=autor,
                      pontuacao={"CRITICA": 9, "ALTA": 7, "MEDIA": 5, "BAIXA": 3}.get(alerta["severidade"], 1))
        salvo = self.repo.inserir_alerta(alerta)
        if self.broadcast and alerta["severidade"] in SEVERIDADES_TEMPO_REAL:
            servidor_alertas.broadcast_alerta(alerta)
        return salvo

    def resumo_dashboard(self):
        return {
            "totais": self.repo.totais(),
            "eventos_por_fonte": self.repo.contagem_por_fonte(),
            "alertas_por_severidade": self.repo.contagem_por_severidade(),
            "top_ips": self.repo.top_ips(10),
            "top_risco_ml": self.repo.listar_scores(10),
        }

    def status(self):
        return {
            "mongo": self.repo.ping(),
            "mysql": self.usuarios.ping() if self.usuarios else False,
            "modelo_integro": verificar_integridade(self.classificador.caminho_modelo),
            "consoles_conectados": servidor_alertas.clientes_conectados(),
        }

    def relatorio_completo(self):
        eventos = self.repo.buscar_eventos({}, 1, 100000)["itens"]
        alertas = self.repo.buscar_alertas({}, 1, 100000)["itens"]
        return {
            "gerado_em": datetime.now().isoformat(timespec="seconds"),
            "plataforma": "SecuraPy Platform",
            "resumo": self.resumo_dashboard(),
            "scores_ml": self.repo.listar_scores(1000),
            "eventos": eventos,
            "alertas": alertas,
        }
