"""
Repositório MongoDB — eventos, alertas e scores de risco (2º sem, Aulas 1–3).

Por que MongoDB aqui: alto volume e schema flexível (cada fonte de log tem
campos diferentes: web tem url/status, firewall tem porta...).

Decisões de projeto:
  - _id determinístico = SHA-256 do conteúdo do evento/alerta. Reingerir os
    mesmos logs NÃO duplica dados (insert_many ordered=False ignora _id repetido).
  - "timestamp" é gravado como datetime (permite filtro por período e índice);
    o texto original fica em "timestamp_original".
  - Índices em ip e timestamp (exigência do enunciado) + TTL opcional.
  - Filtros vindos da API são montados campo a campo a partir de uma lista
    branca — nunca repassamos um dict do usuário direto para o find()
    (evita NoSQL injection do tipo {"$ne": null}).
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import BulkWriteError, PyMongoError

from db import RepositorioIndisponivel

log = logging.getLogger("securapy.db.mongo")

SEVERIDADES = ("CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO")
_DUPLICADO = 11000  # código de chave duplicada do MongoDB
_PESO_SEVERIDADE = {s: len(SEVERIDADES) - i for i, s in enumerate(SEVERIDADES)}


def conectar(uri=None, nome_db=None, timeout_ms=3000):
    """Cria o cliente MongoDB a partir de variáveis de ambiente (sem segredo no código)."""
    uri = uri or os.getenv("MONGO_URI", "mongodb://localhost:27017")
    nome_db = nome_db or os.getenv("MONGO_DB", "securapy")
    if uri.startswith("mongomock://"):  # modo laboratório sem Docker: MongoDB em memória
        import mongomock
        log.warning("MONGO_URI=mongomock:// — dados em memória, perdidos ao encerrar")
        return RepositorioMongo(mongomock.MongoClient()[nome_db])
    cliente = MongoClient(uri, serverSelectionTimeoutMS=timeout_ms)
    return RepositorioMongo(cliente[nome_db])


def _hash(*partes):
    return hashlib.sha256("|".join(str(p) for p in partes).encode("utf-8")).hexdigest()


def _para_datetime(iso):
    if not iso:
        return None
    try:
        return datetime.fromisoformat(str(iso))
    except ValueError:
        return None


def _serializar(doc):
    """Documento do Mongo → dict JSON-friendly (id string, datas ISO)."""
    if doc is None:
        return None
    saida = {}
    for chave, valor in doc.items():
        if chave == "_id":
            saida["id"] = str(valor)
        elif isinstance(valor, datetime):
            saida[chave] = valor.isoformat()
        else:
            saida[chave] = valor
    return saida


class RepositorioMongo:
    """Acesso a dados de eventos/alertas. Recebe o objeto Database (injeção de dependência)."""

    def __init__(self, db):
        self.db = db
        self.eventos = db["eventos"]
        self.alertas = db["alertas"]
        self.scores = db["scores_ip"]

    # ── infraestrutura ──────────────────────────────────────────────────────
    def _executar(self, operacao, *args, **kwargs):
        try:
            return operacao(*args, **kwargs)
        except PyMongoError as e:
            log.error("Falha no MongoDB: %s", e.__class__.__name__)
            raise RepositorioIndisponivel("MongoDB indisponível") from e

    def ping(self):
        try:
            self.db.command("ping")
            return True
        except PyMongoError:
            return False

    def criar_indices(self):
        """Índices exigidos (ip, timestamp) + apoio aos filtros mais usados."""
        self._executar(self.eventos.create_index, [("ip", ASCENDING)], name="idx_ip")
        self._executar(self.eventos.create_index, [("timestamp", ASCENDING)], name="idx_timestamp")
        self._executar(self.eventos.create_index, [("fonte", ASCENDING), ("tipo", ASCENDING)], name="idx_fonte_tipo")
        self._executar(self.alertas.create_index, [("ip", ASCENDING)], name="idx_ip")
        self._executar(self.alertas.create_index, [("timestamp", ASCENDING)], name="idx_timestamp")
        self._executar(self.alertas.create_index, [("severidade", ASCENDING)], name="idx_severidade")
        self._executar(self.scores.create_index, [("score", DESCENDING)], name="idx_score")
        dias_ttl = int(os.getenv("EVENTOS_TTL_DIAS", "0"))
        if dias_ttl > 0:  # retenção automática (Aula 2, seção 2.4)
            self._executar(self.eventos.create_index, [("ingerido_em", ASCENDING)],
                           expireAfterSeconds=dias_ttl * 86400, name="ttl_ingerido_em")

    def limpar(self):
        """Apaga tudo (usado em testes e no reset do laboratório)."""
        for colecao in (self.eventos, self.alertas, self.scores):
            self._executar(colecao.delete_many, {})

    # ── escrita ─────────────────────────────────────────────────────────────
    @staticmethod
    def _preparar_evento(evento):
        doc = dict(evento)
        doc["_id"] = _hash(doc.get("fonte"), doc.get("linha_original") or json.dumps(evento, sort_keys=True, default=str))
        doc["timestamp_original"] = doc.get("timestamp")
        doc["timestamp"] = _para_datetime(doc.get("timestamp_iso"))
        return doc

    @staticmethod
    def _preparar_alerta(alerta):
        doc = dict(alerta)
        doc.pop("id", None)
        doc["_id"] = doc.get("_id") or _hash(doc.get("regra_id"), doc.get("ip"), doc.get("timestamp_iso"),
                                             doc.get("descricao"), doc.get("evento_original"))
        doc["timestamp_original"] = doc.get("timestamp")
        doc["timestamp"] = _para_datetime(doc.get("timestamp_iso"))
        doc["peso_severidade"] = _PESO_SEVERIDADE.get(doc.get("severidade"), 0)
        return doc

    def _upsert_lote(self, colecao, docs):
        if not docs:
            return {"inseridos": 0, "duplicados": 0}
        agora = datetime.now(timezone.utc).replace(tzinfo=None)
        unicos = {}
        for doc in docs:  # dedup dentro do próprio lote
            doc.setdefault("ingerido_em", agora)
            unicos.setdefault(doc["_id"], doc)
        try:
            # ordered=False: insere todos os novos e só reporta os _id repetidos
            inseridos = len(colecao.insert_many(list(unicos.values()), ordered=False).inserted_ids)
        except BulkWriteError as e:
            erros = e.details.get("writeErrors", [])
            if any(err.get("code") != _DUPLICADO for err in erros):
                log.error("Falha no MongoDB ao gravar lote: %s", e.__class__.__name__)
                raise RepositorioIndisponivel("Falha ao gravar no MongoDB") from e
            inseridos = e.details.get("nInserted", len(unicos) - len(erros))
        except PyMongoError as e:
            log.error("Falha no MongoDB: %s", e.__class__.__name__)
            raise RepositorioIndisponivel("MongoDB indisponível") from e
        return {"inseridos": inseridos, "duplicados": len(docs) - inseridos}

    def salvar_eventos(self, eventos):
        return self._upsert_lote(self.eventos, [self._preparar_evento(e) for e in eventos])

    def salvar_alertas(self, alertas):
        return self._upsert_lote(self.alertas, [self._preparar_alerta(a) for a in alertas])

    def inserir_alerta(self, alerta):
        """Insere um alerta manual (POST /api/alertas) e devolve o documento salvo."""
        doc = dict(alerta)
        doc["_id"] = _hash("manual", json.dumps(alerta, sort_keys=True, default=str), datetime.now().isoformat())
        doc = self._preparar_alerta(doc)
        doc["ingerido_em"] = datetime.now(timezone.utc).replace(tzinfo=None)
        self._executar(self.alertas.insert_one, doc)
        return _serializar(doc)

    def salvar_scores(self, scores):
        """scores: {ip: {score, rotulo, nivel, features}} → upsert por IP."""
        if not scores:
            return 0
        for ip, dados in scores.items():
            self._executar(self.scores.replace_one, {"_id": ip}, dict(dados, ip=ip), upsert=True)
        return len(scores)

    # ── leitura com filtros e paginação ─────────────────────────────────────
    @staticmethod
    def _filtro_eventos(filtros):
        consulta = {}
        for campo in ("fonte", "tipo", "ip"):
            valor = filtros.get(campo)
            if valor:
                consulta[campo] = str(valor)
        periodo = {}
        if filtros.get("inicio"):
            periodo["$gte"] = filtros["inicio"]
        if filtros.get("fim"):
            periodo["$lte"] = filtros["fim"]
        if periodo:
            consulta["timestamp"] = periodo
        return consulta

    @staticmethod
    def _filtro_alertas(filtros):
        consulta = {}
        if filtros.get("severidade"):
            consulta["severidade"] = str(filtros["severidade"]).upper()
        for campo in ("ip", "regra_id", "fonte", "origem"):
            if filtros.get(campo):
                consulta[campo] = str(filtros[campo])
        return consulta

    def _paginar(self, colecao, consulta, ordenacao, pagina, tamanho):
        total = self._executar(colecao.count_documents, consulta)
        cursor = colecao.find(consulta).sort(ordenacao).skip((pagina - 1) * tamanho).limit(tamanho)
        itens = [_serializar(d) for d in self._executar(list, cursor)]
        return {"itens": itens, "total": total, "pagina": pagina, "tamanho": tamanho,
                "paginas": (total + tamanho - 1) // tamanho if tamanho else 0}

    def buscar_eventos(self, filtros=None, pagina=1, tamanho=20):
        return self._paginar(self.eventos, self._filtro_eventos(filtros or {}),
                             [("timestamp", ASCENDING), ("_id", ASCENDING)], pagina, tamanho)

    def buscar_alertas(self, filtros=None, pagina=1, tamanho=20):
        return self._paginar(self.alertas, self._filtro_alertas(filtros or {}),
                             [("peso_severidade", DESCENDING), ("timestamp", DESCENDING), ("_id", ASCENDING)],
                             pagina, tamanho)

    def obter_alerta(self, id_alerta):
        return _serializar(self._executar(self.alertas.find_one, {"_id": str(id_alerta)}))

    def eventos_do_ip(self, ip, limite=500):
        cursor = self.eventos.find({"ip": ip}).sort("timestamp", ASCENDING).limit(limite)
        return [_serializar(d) for d in self._executar(list, cursor)]

    def alertas_do_ip(self, ip, limite=500):
        cursor = self.alertas.find({"ip": ip}).sort("peso_severidade", DESCENDING).limit(limite)
        return [_serializar(d) for d in self._executar(list, cursor)]

    def obter_score(self, ip):
        doc = self._executar(self.scores.find_one, {"_id": ip})
        if doc:
            doc.pop("_id", None)
        return doc

    def listar_scores(self, limite=10):
        cursor = self.scores.find({}, {"_id": 0}).sort("score", DESCENDING).limit(limite)
        return self._executar(list, cursor)

    # ── agregações ──────────────────────────────────────────────────────────
    def top_ips(self, limite=5):
        """Top N IPs por quantidade de eventos (B2)."""
        pipeline = [
            {"$group": {"_id": "$ip", "eventos": {"$sum": 1}, "fontes": {"$addToSet": "$fonte"}}},
            {"$sort": {"eventos": -1, "_id": 1}},
            {"$limit": int(limite)},
        ]
        return [{"ip": d["_id"], "eventos": d["eventos"], "fontes": sorted(d["fontes"])}
                for d in self._executar(lambda: list(self.eventos.aggregate(pipeline)))]

    def contagem_por_severidade(self):
        pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
        brutos = {d["_id"]: d["total"] for d in self._executar(lambda: list(self.alertas.aggregate(pipeline)))}
        return {s: brutos.get(s, 0) for s in SEVERIDADES}

    def contagem_por_fonte(self):
        pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}, {"$sort": {"_id": 1}}]
        return {d["_id"]: d["total"] for d in self._executar(lambda: list(self.eventos.aggregate(pipeline)))}

    def totais(self):
        return {
            "eventos": self._executar(self.eventos.count_documents, {}),
            "alertas": self._executar(self.alertas.count_documents, {}),
            "ips_pontuados": self._executar(self.scores.count_documents, {}),
        }
