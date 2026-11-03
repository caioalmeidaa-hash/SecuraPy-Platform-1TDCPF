"""
Dashboard web dos analistas (2º sem — Aulas 6 e 8).

Segurança:
  - Jinja2 com autoescape (padrão para .html) → XSS armazenado vira texto (E1).
  - Nenhum JavaScript/CSS inline → a CSP pode proibir 'unsafe-inline'.
  - Login com mensagem genérica, sessão regenerada (session.clear) e cookie
    HttpOnly + SameSite; formulários POST protegidos por token CSRF.
"""

import hmac
import secrets
from functools import wraps

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from api import validacao as v
from api.servico import ErroEntrada
from db import RepositorioIndisponivel

web_bp = Blueprint("web", __name__)


def _servico():
    return current_app.extensions["securapy"]


def _token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@web_bp.app_context_processor
def _contexto():
    return {"csrf_token": _token_csrf, "operador": session.get("usuario")}


def _validar_csrf():
    enviado = request.form.get("csrf", "")
    if not enviado or not hmac.compare_digest(enviado, session.get("csrf", "")):
        abort(400)


def login_obrigatorio(nivel_minimo=1):
    def decorador(funcao):
        @wraps(funcao)
        def interna(*args, **kwargs):
            usuario = session.get("usuario")
            if not usuario:
                return redirect(url_for("web.login"))
            if usuario["nivel"] < nivel_minimo:
                abort(403)
            g.usuario = {"email": usuario["email"]}
            if request.method == "POST":
                _validar_csrf()
            return funcao(*args, **kwargs)
        return interna
    return decorador


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method != "POST":
        return render_template("login.html")
    _validar_csrf()
    email = request.form.get("email", "")[:254]
    chave = f"{request.remote_addr}|{email.lower()}"
    if g.limitador.bloqueado(chave):
        return render_template("login.html", erro="Muitas tentativas. Aguarde alguns minutos."), 429
    try:
        usuario = _servico().usuarios.autenticar(email, request.form.get("senha", ""))
    except RepositorioIndisponivel:
        return render_template("login.html", erro="Serviço temporariamente indisponível."), 503
    if not usuario:
        g.limitador.registrar_falha(chave)
        return render_template("login.html", erro="Credenciais inválidas."), 401
    g.limitador.limpar(chave)
    session.clear()  # evita fixação de sessão
    session["usuario"] = {"id": usuario["id"], "nome": usuario["nome"], "email": usuario["email"],
                          "nivel": int(usuario["nivel_acesso"])}
    return redirect(url_for("web.dashboard"))


@web_bp.post("/logout")
def logout():
    _validar_csrf()
    session.clear()
    return redirect(url_for("web.login"))


@web_bp.get("/")
@login_obrigatorio()
def dashboard():
    resumo = _servico().resumo_dashboard()
    recentes = _servico().repo.buscar_alertas({}, 1, 15)["itens"]
    maior_fonte = max(resumo["eventos_por_fonte"].values(), default=0) or 1
    maior_sev = max(resumo["alertas_por_severidade"].values(), default=0) or 1
    return render_template("dashboard.html", resumo=resumo, recentes=recentes,
                           maior_fonte=maior_fonte, maior_sev=maior_sev)


@web_bp.get("/ip")
@login_obrigatorio()
def buscar_ip():
    bruto = request.args.get("ip", "")
    try:
        ip = v.validar_ip(bruto)
    except v.ErroValidacao:
        return render_template("erro.html", codigo=400,
                               mensagem="IP inválido. Use o formato 203.0.113.10 ou um IPv6."), 400
    detalhes = _servico().detalhes_ip(ip)
    return render_template("ip.html", ip=ip, d=detalhes), (200 if detalhes else 404)


@web_bp.get("/alertas")
@login_obrigatorio()
def alertas():
    pagina, tamanho = v.paginacao(request.args)
    filtros = v.filtros_alertas(request.args)
    dados = _servico().repo.buscar_alertas(filtros, pagina, tamanho)
    return render_template("alertas.html", dados=dados, filtros=filtros, severidades=v.SEVERIDADES)


@web_bp.post("/alertas/novo")
@login_obrigatorio(nivel_minimo=3)
def novo_alerta():
    try:
        alerta = v.corpo_alerta(request.form.to_dict())
    except v.ErroValidacao as e:
        flash(str(e), "erro")
        return redirect(url_for("web.alertas"))
    _servico().criar_alerta_manual(alerta, autor=session["usuario"]["email"])
    flash("Alerta cadastrado.", "ok")
    return redirect(url_for("web.alertas"))


@web_bp.post("/analisar")
@login_obrigatorio(nivel_minimo=3)
def analisar():
    try:
        r = _servico().analisar({})
    except ErroEntrada as e:
        flash(str(e), "erro")
        return redirect(url_for("web.dashboard"))
    flash(f"Análise concluída: {r['eventos_processados']} eventos, {r['alertas_gerados']} alertas, "
          f"{len(r['ameacas'])} ameaças, {r['alertas_tempo_real_enviados']} alertas enviados em tempo real.", "ok")
    return redirect(url_for("web.dashboard"))
