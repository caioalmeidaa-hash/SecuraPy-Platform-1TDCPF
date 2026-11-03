"""
Repositório MySQL — usuários e permissões da plataforma (2º sem, Aula 3).

Por que MySQL aqui: dados pequenos que exigem integridade relacional
(email único, nível de acesso válido via FOREIGN KEY + CHECK).

Regras de segurança aplicadas:
  - 100% das queries são PARAMETRIZADAS (%s + tupla de parâmetros). Nenhum
    valor vindo do usuário é concatenado em SQL → SQL Injection neutralizado (B4).
  - Senha nunca é armazenada: só o hash (werkzeug: scrypt/pbkdf2 com salt).
  - Login responde igual para "usuário não existe" e "senha errada" e gasta
    o mesmo tempo nos dois casos (verifica contra um hash fictício) → sem
    enumeração de usuários.
  - Email duplicado vira RegistroDuplicado (B3) — a aplicação não quebra.
  - Credenciais do banco vêm de variáveis de ambiente.
"""

import logging
import os
import re
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor
from werkzeug.security import check_password_hash, generate_password_hash

from db import RegistroDuplicado, RepositorioIndisponivel

log = logging.getLogger("securapy.db.mysql")

NIVEL_MIN, NIVEL_MAX = 1, 5
_RE_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[A-Za-z]{2,}$")
# Hash fictício usado quando o usuário não existe (mesmo custo de verificação)
_HASH_FICTICIO = generate_password_hash("securapy-senha-ficticia")
_ERRO_DUPLICADO = 1062
_CAMPOS_PUBLICOS = "id, nome, email, nivel_acesso, ativo, criado_em, ultimo_login"


def config_do_ambiente():
    return {
        "host": os.getenv("MYSQL_HOST", "localhost"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "securapy"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "database": os.getenv("MYSQL_DATABASE", "securapy"),
    }


def validar_senha(senha):
    """Política mínima: 8+ caracteres, com letra e número."""
    return (isinstance(senha, str) and len(senha) >= 8
            and any(c.isalpha() for c in senha) and any(c.isdigit() for c in senha))


class RepositorioUsuarios:
    def __init__(self, config=None):
        self.config = dict(config or config_do_ambiente())

    @contextmanager
    def _cursor(self):
        """Abre conexão + cursor; faz commit/rollback e converte erros de conexão."""
        try:
            conexao = pymysql.connect(charset="utf8mb4", cursorclass=DictCursor,
                                      connect_timeout=5, autocommit=False, **self.config)
        except pymysql.err.OperationalError as e:
            log.error("MySQL indisponível (código %s)", e.args[0] if e.args else "?")
            raise RepositorioIndisponivel("MySQL indisponível") from e
        try:
            with conexao.cursor() as cursor:
                yield cursor
            conexao.commit()
        except pymysql.err.IntegrityError as e:
            conexao.rollback()
            if e.args and e.args[0] == _ERRO_DUPLICADO:
                raise RegistroDuplicado("Email já cadastrado") from e
            raise
        except pymysql.err.OperationalError as e:
            conexao.rollback()
            raise RepositorioIndisponivel("Falha na operação MySQL") from e
        except Exception:
            conexao.rollback()
            raise
        finally:
            conexao.close()

    def ping(self):
        try:
            with self._cursor() as c:
                c.execute("SELECT 1")
            return True
        except RepositorioIndisponivel:
            return False

    def criar_tabelas(self):
        caminho = os.path.join(os.path.dirname(os.path.abspath(__file__)), "init.sql")
        with open(caminho, encoding="utf-8") as f:
            comandos = [c.strip() for c in f.read().split(";")]
        with self._cursor() as c:
            for comando in comandos:
                linhas = [l for l in comando.splitlines() if not l.strip().startswith("--")]
                sql = "\n".join(linhas).strip()
                if sql:
                    c.execute(sql)

    # ── CRUD ────────────────────────────────────────────────────────────────
    def criar_usuario(self, nome, email, senha, nivel_acesso=1):
        nome = (nome or "").strip()
        email = (email or "").strip().lower()
        if not nome or len(nome) > 100:
            raise ValueError("Nome inválido")
        if not _RE_EMAIL.match(email):
            raise ValueError("Email inválido")
        if not validar_senha(senha):
            raise ValueError("Senha fraca: mínimo 8 caracteres com letras e números")
        if not isinstance(nivel_acesso, int) or not NIVEL_MIN <= nivel_acesso <= NIVEL_MAX:
            raise ValueError("Nível de acesso deve ser de 1 a 5")

        with self._cursor() as c:
            c.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) VALUES (%s, %s, %s, %s)",
                (nome, email, generate_password_hash(senha), nivel_acesso),
            )
            return c.lastrowid

    def buscar_por_email(self, email):
        with self._cursor() as c:
            c.execute(f"SELECT {_CAMPOS_PUBLICOS} FROM usuarios WHERE email = %s", ((email or "").strip().lower(),))
            return c.fetchone()

    def buscar_por_id(self, id_usuario):
        with self._cursor() as c:
            c.execute(f"SELECT {_CAMPOS_PUBLICOS} FROM usuarios WHERE id = %s", (int(id_usuario),))
            return c.fetchone()

    def listar_usuarios(self):
        with self._cursor() as c:
            c.execute(f"SELECT {_CAMPOS_PUBLICOS} FROM usuarios ORDER BY id")
            return c.fetchall()

    def atualizar_nivel(self, id_usuario, nivel_acesso):
        if not isinstance(nivel_acesso, int) or not NIVEL_MIN <= nivel_acesso <= NIVEL_MAX:
            raise ValueError("Nível de acesso deve ser de 1 a 5")
        with self._cursor() as c:
            return c.execute("UPDATE usuarios SET nivel_acesso = %s WHERE id = %s", (nivel_acesso, int(id_usuario)))

    def alterar_senha(self, id_usuario, nova_senha):
        if not validar_senha(nova_senha):
            raise ValueError("Senha fraca: mínimo 8 caracteres com letras e números")
        with self._cursor() as c:
            return c.execute("UPDATE usuarios SET senha_hash = %s WHERE id = %s",
                             (generate_password_hash(nova_senha), int(id_usuario)))

    def desativar_usuario(self, id_usuario):
        with self._cursor() as c:
            return c.execute("UPDATE usuarios SET ativo = FALSE WHERE id = %s", (int(id_usuario),))

    def remover_usuario(self, id_usuario):
        with self._cursor() as c:
            return c.execute("DELETE FROM usuarios WHERE id = %s", (int(id_usuario),))

    # ── autenticação ────────────────────────────────────────────────────────
    def autenticar(self, email, senha):
        """
        Retorna os dados públicos do usuário se email+senha conferem; senão None.
        Mesmo comportamento (e custo) para usuário inexistente e senha errada.
        """
        if not isinstance(email, str) or not isinstance(senha, str) or len(email) > 254 or len(senha) > 256:
            check_password_hash(_HASH_FICTICIO, "x")
            return None
        with self._cursor() as c:
            c.execute(
                f"SELECT {_CAMPOS_PUBLICOS}, senha_hash FROM usuarios WHERE email = %s AND ativo = TRUE",
                (email.strip().lower(),),
            )
            linha = c.fetchone()
            hash_alvo = linha["senha_hash"] if linha else _HASH_FICTICIO
            senha_ok = check_password_hash(hash_alvo, senha)
            if not (linha and senha_ok):
                return None
            c.execute("UPDATE usuarios SET ultimo_login = CURRENT_TIMESTAMP WHERE id = %s", (linha["id"],))
            linha.pop("senha_hash")
            return linha

    def garantir_admin(self, email, senha, nome="Administrador"):
        """Cria o admin inicial (vindo de variáveis de ambiente) se ainda não existir."""
        if not email or not senha:
            return False
        try:
            self.criar_usuario(nome, email, senha, NIVEL_MAX)
            log.info("Usuário admin inicial criado")
            return True
        except RegistroDuplicado:
            return False
