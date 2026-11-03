"""Alertas em tempo real — 2 consoles recebem o mesmo broadcast (servidor TCP do 1º sem)."""

import socket
import threading
import time

from alertas import servidor_alertas


def _porta_livre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ler_ate(sock, trecho, timeout=3):
    sock.settimeout(timeout)
    dados = b""
    fim = time.time() + timeout
    while trecho.encode() not in dados and time.time() < fim:
        try:
            dados += sock.recv(4096)
        except socket.timeout:
            break
    return dados.decode("utf-8", errors="ignore")


def test_broadcast_para_dois_consoles():
    porta = _porta_livre()
    threading.Thread(target=servidor_alertas.iniciar_servidor, args=("127.0.0.1", porta), daemon=True).start()
    time.sleep(0.3)
    consoles = [socket.create_connection(("127.0.0.1", porta)) for _ in range(2)]
    for c in consoles:
        _ler_ate(c, "/sair")  # boas-vindas
    time.sleep(0.2)
    servidor_alertas.broadcast_alerta({"timestamp": "08:15", "severidade": "CRITICA", "regra_nome": "Ameaça consolidada",
                                       "ip": "185.220.101.1", "descricao": "brute force + port scan + blacklist"})
    for c in consoles:
        recebido = _ler_ate(c, "185.220.101.1")
        assert "[CRITICA] Ameaça consolidada — 185.220.101.1" in recebido
        c.sendall(b"/sair")
        c.close()
