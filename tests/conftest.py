"""Fixtures compartilhadas. MongoDB via mongomock; MySQL real quando disponível."""

import os
import sys

import mongomock
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

os.environ.setdefault("ENRIQUECIMENTO_OFFLINE", "1")
os.environ.setdefault("LLM_MODO", "mock")
os.environ["ALERTAS_TCP"] = "0"
os.environ.setdefault("JWT_SECRET", "segredo-de-teste-com-mais-de-32-caracteres!!")
os.environ.setdefault("FLASK_SECRET_KEY", "outro-segredo-de-teste-com-mais-de-32-chars")
os.environ.setdefault("LOG_ACESSO", os.path.join(RAIZ, "var", "acesso_testes.log"))

from core.pipeline import analisar_pasta  # noqa: E402
from db import RegistroDuplicado  # noqa: E402
from db.mongo_repo import RepositorioMongo  # noqa: E402

BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


class UsuariosEmMemoria:
    """Dublê do RepositorioUsuarios (mesma interface) para testar a API sem MySQL."""

    def __init__(self):
        self._por_email = {}

    def ping(self):
        return True

    def criar_tabelas(self):
        pass

    def garantir_admin(self, *a, **k):
        return False

    def criar_usuario(self, nome, email, senha, nivel_acesso=1):
        email = email.lower()
        if email in self._por_email:
            raise RegistroDuplicado("Email já cadastrado")
        uid = len(self._por_email) + 1
        self._por_email[email] = {"id": uid, "nome": nome, "email": email, "nivel_acesso": nivel_acesso,
                                  "senha_hash": generate_password_hash(senha)}
        return uid

    def autenticar(self, email, senha):
        u = self._por_email.get(str(email).lower())
        if not u or not check_password_hash(u["senha_hash"], str(senha)):
            return None
        return {k: v for k, v in u.items() if k != "senha_hash"}

    def listar_usuarios(self):
        return [{k: v for k, v in u.items() if k != "senha_hash"} for u in self._por_email.values()]


@pytest.fixture(scope="session")
def analise():
    return analisar_pasta(os.path.join(RAIZ, "logs"), blacklist=set(BLACKLIST))


@pytest.fixture(scope="session")
def eventos(analise):
    return analise["eventos"]


@pytest.fixture
def repo_mongo():
    return RepositorioMongo(mongomock.MongoClient()["securapy_teste"])


@pytest.fixture
def usuarios():
    u = UsuariosEmMemoria()
    u.criar_usuario("Admin", "admin@cybershield.com", "Admin12345", 5)
    u.criar_usuario("Leitor", "leitor@cybershield.com", "Leitor12345", 1)
    return u


@pytest.fixture
def app(repo_mongo, usuarios):
    from api.app import create_app
    app = create_app(repo_eventos=repo_mongo, repo_usuarios=usuarios, config={"TESTING": True})
    return app


@pytest.fixture
def cliente(app):
    return app.test_client()


def _token(cliente, email, senha):
    r = cliente.post("/api/login", json={"email": email, "senha": senha})
    assert r.status_code == 200, r.json
    return {"Authorization": f"Bearer {r.json['token']}"}


@pytest.fixture
def h_admin(cliente):
    return _token(cliente, "admin@cybershield.com", "Admin12345")


@pytest.fixture
def h_leitor(cliente):
    return _token(cliente, "leitor@cybershield.com", "Leitor12345")


@pytest.fixture
def cliente_com_dados(cliente, h_admin):
    r = cliente.post("/api/analisar", headers=h_admin, json={})
    assert r.status_code == 200, r.json
    return cliente
