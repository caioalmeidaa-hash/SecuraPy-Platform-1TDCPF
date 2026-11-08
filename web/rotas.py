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


@web_bp.post("/analisar/upload")
@login_obrigatorio(nivel_minimo=3)
def analisar_upload():
    arquivo = request.files.get("arquivo")
    if arquivo is None or not arquivo.filename:
        flash("Escolha um arquivo de log antes de enviar.", "erro")
        return redirect(url_for("web.dashboard"))
    texto = arquivo.read().decode("utf-8", errors="replace")
    try:
        r = _servico().analisar_texto(texto, request.form.get("fonte", "auto"))
    except ErroEntrada as e:
        flash(str(e), "erro")
        return redirect(url_for("web.dashboard"))
    flash(f"Arquivo analisado: {r['eventos_processados']} eventos, {r['alertas_gerados']} alertas, "
          f"{len(r['ameacas'])} ameacas, {r['linhas_ignoradas']} linhas ignoradas.", "ok")
    return redirect(url_for("web.dashboard"))


@web_bp.get("/ao-vivo")
@login_obrigatorio()
def ao_vivo():
    return render_template("ao_vivo.html")


@web_bp.post("/ao-vivo/zerar")
@login_obrigatorio(nivel_minimo=5)
def zerar_dados():
    """Apaga eventos, alertas e scores (só admin) — para começar a demonstração do zero."""
    _servico().repo.limpar()
    flash("Dados apagados. Rode o simulador de ataque para ver o painel reagir.", "ok")
    return redirect(url_for("web.ao_vivo"))


@web_bp.post("/ao-vivo/ia")
@login_obrigatorio()
def boletim_ia():
    """Botão "Analisar com IA" da tela Ao vivo: boletim da situação em linguagem simples."""
    from flask import jsonify
    from ia.resumo import gerar_boletim
    return jsonify(gerar_boletim(_servico().repo))


@web_bp.post("/ip/diagnostico")
@login_obrigatorio()
def diagnostico_ip():
    """Botão "Onde está a falha e como corrigir" da página do IP."""
    from flask import jsonify
    from ia.diagnostico import diagnosticar
    ip = v.validar_ip(request.form.get("ip", ""))
    return jsonify(diagnosticar(_servico().repo, ip))


@web_bp.get("/conectar")
@login_obrigatorio()
def conectar():
    """Passo a passo (linguagem simples) para ligar um servidor de verdade ao SecuraPy."""
    import os
    from datetime import datetime
    agora = datetime.now()
    coletores = []
    for c in sorted(_servico().coletores.values(), key=lambda x: x["ultimo_envio"], reverse=True):
        segundos = int((agora - datetime.fromisoformat(c["ultimo_envio"])).total_seconds())
        coletores.append(dict(c, segundos=segundos, online=segundos < 120))
    endereco = request.host_url.rstrip("/")
    from notificacoes import telegram
    return render_template("conectar.html", endereco=endereco, coletores=coletores,
                           email=session["usuario"]["email"], telegram_ok=telegram.configurado(),
                           tem_token=bool(os.getenv("TELEGRAM_BOT_TOKEN")))


@web_bp.get("/conectar/coletor.py")
def baixar_coletor():
    """Entrega o script do coletor (público: não contém segredo nenhum)."""
    import os
    from flask import send_file
    raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return send_file(os.path.join(raiz, "scripts", "coletor.py"), mimetype="text/x-python",
                     as_attachment=True, download_name="coletor.py")


@web_bp.get("/assistente")
@login_obrigatorio()
def assistente():
    return render_template("assistente.html")


@web_bp.post("/assistente/perguntar")
@login_obrigatorio()
def perguntar():
    """Chat "Pergunte ao SecuraPy": resposta em linguagem simples, só com os dados reais."""
    import json
    from flask import jsonify
    from ia.chat import responder
    try:
        historico = json.loads(request.form.get("historico", "[]"))
    except ValueError:
        historico = []
    if not isinstance(historico, list):
        historico = []
    historico = [m for m in historico[-4:] if isinstance(m, dict)]
    return jsonify(responder(_servico().repo, request.form.get("pergunta", ""), historico))


@web_bp.post("/notificacoes/teste")
@login_obrigatorio(nivel_minimo=3)
def telegram_teste():
    from notificacoes import telegram
    ok, detalhe = telegram.enviar("✅ SecuraPy conectado! A partir de agora você recebe aqui os alertas críticos "
                                  "da sua empresa, em linguagem simples.")
    flash(("Telegram: " if ok else "Telegram — erro: ") + detalhe, "ok" if ok else "erro")
    return redirect(url_for("web.conectar") + "#telegram")


@web_bp.post("/notificacoes/descobrir")
@login_obrigatorio(nivel_minimo=3)
def telegram_descobrir():
    from notificacoes import telegram
    ok, detalhe, chats = telegram.descobrir_chats()
    if chats:
        detalhe += " " + "; ".join(f"{c['nome']}: TELEGRAM_CHAT_ID={c['id']}" for c in chats)
    flash("Telegram: " + detalhe, "ok" if ok else "erro")
    return redirect(url_for("web.conectar") + "#telegram")
