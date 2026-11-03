"""Módulo E — segurança web e dashboard (cenários E1–E4)."""

import os
import re

PAYLOAD = "<script>alert(1)</script>"


def _csrf(html):
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def _login_web(cliente, email="admin@cybershield.com", senha="Admin12345"):
    token = _csrf(cliente.get("/login").get_data(as_text=True))
    return cliente.post("/login", data={"email": email, "senha": senha, "csrf": token})


def test_e1_xss_armazenado_e_exibido_como_texto(cliente_com_dados, h_admin):
    r = cliente_com_dados.post("/api/alertas", headers=h_admin, json={
        "ip": "203.0.113.66", "severidade": "CRITICA", "regra_nome": "Teste <b>XSS</b>", "descricao": PAYLOAD})
    assert r.status_code == 201
    _login_web(cliente_com_dados)
    for rota in ("/", "/alertas?severidade=critica", "/ip?ip=203.0.113.66"):
        html = cliente_com_dados.get(rota).get_data(as_text=True)
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html, rota
        assert PAYLOAD not in html, rota


def test_e2_headers_de_seguranca_em_todas_as_respostas(cliente):
    for rota in ("/api/saude", "/login", "/api/ip/abc", "/rota-inexistente"):
        r = cliente.get(rota)
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]
        assert "unsafe-inline" not in r.headers["Content-Security-Policy"]


def test_e3_login_web_mensagem_generica(cliente):
    errada = _login_web(cliente, "admin@cybershield.com", "senhaErrada1")
    inexistente = _login_web(cliente, "fantasma@cybershield.com", "senhaErrada1")
    assert errada.status_code == inexistente.status_code == 401
    assert "Credenciais inválidas." in errada.get_data(as_text=True)
    assert "Credenciais inválidas." in inexistente.get_data(as_text=True)


def test_login_web_exige_csrf_e_protege_dashboard(cliente):
    assert cliente.get("/").status_code == 302  # sem sessão → login
    assert cliente.post("/login", data={"email": "admin@cybershield.com", "senha": "Admin12345"}).status_code == 400
    assert _login_web(cliente).status_code == 302
    r = cliente.get("/")
    assert r.status_code == 200 and "Visão geral" in r.get_data(as_text=True)
    assert "HttpOnly" in cliente.get("/login").headers.get("Set-Cookie", "HttpOnly")


def test_e4_cada_requisicao_gera_linha_de_log(cliente, app):
    caminho = app.config["LOG_ACESSO"]
    antes = os.path.getsize(caminho) if os.path.exists(caminho) else 0
    cliente.get("/api/saude")
    cliente.get("/api/ip/abc")
    with open(caminho, encoding="utf-8") as f:
        f.seek(antes)
        novas = f.read().strip().splitlines()
    assert any("rota=/api/saude status=200" in l for l in novas)
    assert any("rota=/api/ip/abc status=400" in l for l in novas)
    assert not any("Bearer" in l for l in novas)


def test_busca_ip_invalido_no_dashboard(cliente):
    _login_web(cliente)
    r = cliente.get("/ip?ip=<script>")
    assert r.status_code == 400 and "<script>" not in r.get_data(as_text=True)
