"""Módulo B — MongoDB (mongomock) e MySQL (real, se disponível)."""

import os
import uuid

import pytest

from db import RegistroDuplicado


def test_b1_ingere_58_eventos(repo_mongo, analise):
    r = repo_mongo.salvar_eventos(analise["eventos"])
    assert r == {"inseridos": 58, "duplicados": 0}
    assert repo_mongo.contagem_por_fonte() == {"auth": 23, "firewall": 17, "web": 18}


def test_reingestao_e_idempotente(repo_mongo, analise):
    repo_mongo.salvar_eventos(analise["eventos"])
    assert repo_mongo.salvar_eventos(analise["eventos"]) == {"inseridos": 0, "duplicados": 58}
    assert repo_mongo.totais()["eventos"] == 58


def test_b2_top5_ips(repo_mongo, analise):
    repo_mongo.salvar_eventos(analise["eventos"])
    top = repo_mongo.top_ips(5)
    assert len(top) == 5 and top[0]["ip"] == "185.220.101.1"


def test_filtros_paginacao_e_indices(repo_mongo, analise):
    from datetime import datetime
    repo_mongo.criar_indices()
    repo_mongo.salvar_eventos(analise["eventos"])
    nomes = {i["name"] for i in repo_mongo.eventos.list_indexes()}
    assert {"idx_ip", "idx_timestamp"} <= nomes
    pagina = repo_mongo.buscar_eventos({"fonte": "auth", "tipo": "FAIL"}, pagina=2, tamanho=5)
    assert pagina["total"] == 19 and len(pagina["itens"]) == 5 and pagina["paginas"] == 4
    periodo = repo_mongo.buscar_eventos({"inicio": datetime(2025, 2, 20, 8, 20), "fim": datetime(2025, 2, 20, 8, 21)})
    assert periodo["total"] > 0 and all(e["fonte"] == "web" for e in periodo["itens"])


def test_filtro_nao_aceita_operador_nosql(repo_mongo, analise):
    repo_mongo.salvar_eventos(analise["eventos"])
    # um dict malicioso vira string literal — não vira operador $ne
    assert repo_mongo.buscar_eventos({"ip": {"$ne": None}})["total"] == 0


def test_contagem_por_severidade(repo_mongo, analise):
    repo_mongo.salvar_alertas(analise["alertas"])
    contagem = repo_mongo.contagem_por_severidade()
    assert contagem["CRITICA"] >= 1 and sum(contagem.values()) == len(analise["alertas"])


# ── MySQL real (pula se não houver servidor) ─────────────────────────────────
@pytest.fixture
def repo_mysql():
    from db.mysql_repo import RepositorioUsuarios
    repo = RepositorioUsuarios()
    if not os.getenv("MYSQL_PASSWORD") or not repo.ping():
        pytest.skip("MySQL indisponível (defina MYSQL_HOST/MYSQL_USER/MYSQL_PASSWORD/MYSQL_DATABASE)")
    repo.criar_tabelas()
    return repo


def test_b3_email_duplicado_tratado(repo_mysql):
    email = f"dup-{uuid.uuid4().hex[:8]}@cybershield.com"
    uid = repo_mysql.criar_usuario("Ana", email, "Senha1234", 3)
    try:
        with pytest.raises(RegistroDuplicado):
            repo_mysql.criar_usuario("Outra Ana", email.upper(), "Senha1234", 1)
    finally:
        repo_mysql.remover_usuario(uid)


def test_b4_sql_injection_no_login_neutralizado(repo_mysql):
    email = f"sqli-{uuid.uuid4().hex[:8]}@cybershield.com"
    uid = repo_mysql.criar_usuario("Bia", email, "Senha1234", 1)
    try:
        assert repo_mysql.autenticar("' OR '1'='1", "' OR '1'='1") is None
        assert repo_mysql.autenticar(f"{email}' -- ", "qualquer") is None
        assert repo_mysql.autenticar(email, "Senha1234")["email"] == email
    finally:
        repo_mysql.remover_usuario(uid)


def test_validacoes_de_usuario(repo_mysql):
    with pytest.raises(ValueError):
        repo_mysql.criar_usuario("X", "sem-arroba", "Senha1234", 1)
    with pytest.raises(ValueError):
        repo_mysql.criar_usuario("X", "x@y.com", "fraca", 1)
    with pytest.raises(ValueError):
        repo_mysql.criar_usuario("X", "x@y.com", "Senha1234", 9)
