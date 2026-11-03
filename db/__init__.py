"""Camada de persistência — exceções compartilhadas pelos repositórios."""


class ErroRepositorio(Exception):
    """Erro genérico de persistência (mensagem segura para log, nunca para o cliente)."""


class RepositorioIndisponivel(ErroRepositorio):
    """Banco fora do ar / falha de conexão."""


class RegistroDuplicado(ErroRepositorio):
    """Violação de unicidade (ex.: email já cadastrado)."""
