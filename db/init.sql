-- SecuraPy Platform — schema MySQL (usuários e permissões)
-- Executado automaticamente pelo contêiner mysql (docker-entrypoint-initdb.d)
-- e também por RepositorioUsuarios.criar_tabelas().

CREATE TABLE IF NOT EXISTS niveis_acesso (
    nivel       TINYINT UNSIGNED PRIMARY KEY,
    nome        VARCHAR(30)  NOT NULL UNIQUE,
    descricao   VARCHAR(200) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO niveis_acesso (nivel, nome, descricao) VALUES
    (1, 'leitura',     'Consulta dashboard e API (somente leitura)'),
    (2, 'analista_jr', 'Leitura + uso do assistente LLM'),
    (3, 'analista',    'Cadastra alertas e dispara análises'),
    (4, 'lider',       'Analista + gestão de regras'),
    (5, 'admin',       'Acesso total, inclusive gestão de usuários');

CREATE TABLE IF NOT EXISTS usuarios (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    nome          VARCHAR(100) NOT NULL,
    email         VARCHAR(254) NOT NULL,
    senha_hash    VARCHAR(255) NOT NULL,
    nivel_acesso  TINYINT UNSIGNED NOT NULL DEFAULT 1,
    ativo         BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ultimo_login  TIMESTAMP NULL,
    CONSTRAINT uq_usuarios_email UNIQUE (email),
    CONSTRAINT fk_usuarios_nivel FOREIGN KEY (nivel_acesso) REFERENCES niveis_acesso (nivel),
    CONSTRAINT ck_usuarios_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
