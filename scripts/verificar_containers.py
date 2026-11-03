"""
Verificação dos contêineres via Docker SDK (Módulo F — cenários F2 e F3).

  F2: lista os 3 serviços do compose (api, mongo, mysql) e confirma "running".
  F3: chama GET /api/saude e confirma HTTP 200.

Uso (com o compose no ar):  python scripts/verificar_containers.py
"""

import os
import sys

import requests

SERVICOS = ("api", "mongo", "mysql")
PROJETO = os.getenv("COMPOSE_PROJECT_NAME", "securapy")
URL_SAUDE = os.getenv("URL_SAUDE", "http://localhost:5000/api/saude")


def verificar_containers():
    import docker
    from docker.errors import DockerException

    try:
        cliente = docker.from_env()
        cliente.ping()
    except DockerException:
        print("[ERRO] Não foi possível falar com o Docker. O Docker Desktop/daemon está rodando?")
        return False

    tudo_ok = True
    print(f"{'SERVIÇO':8s} {'CONTÊINER':28s} {'STATUS':10s} {'SAÚDE':10s}")
    for servico in SERVICOS:
        filtros = {"label": [f"com.docker.compose.project={PROJETO}", f"com.docker.compose.service={servico}"]}
        conteineres = cliente.containers.list(all=True, filters=filtros)
        if not conteineres:
            print(f"{servico:8s} {'(não encontrado)':28s} {'-':10s}")
            tudo_ok = False
            continue
        for c in conteineres:
            saude = c.attrs.get("State", {}).get("Health", {}).get("Status", "-")
            print(f"{servico:8s} {c.name:28s} {c.status:10s} {saude:10s}")
            tudo_ok &= c.status == "running"
    return tudo_ok


def verificar_api():
    try:
        r = requests.get(URL_SAUDE, timeout=5)
    except requests.RequestException as e:
        print(f"[ERRO] API não respondeu em {URL_SAUDE} ({e.__class__.__name__})")
        return False
    print(f"\nGET {URL_SAUDE} → {r.status_code} {r.json() if r.ok else ''}")
    return r.status_code == 200


if __name__ == "__main__":
    ok = verificar_containers()
    ok = verificar_api() and ok
    print("\nResultado:", "TUDO OK ✅" if ok else "FALHOU ❌")
    sys.exit(0 if ok else 1)
