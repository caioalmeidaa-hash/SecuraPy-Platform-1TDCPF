// Tela "Ao vivo": consulta /api/ao-vivo a cada 2 s e anima o painel.
// Tudo que vem do log é escrito com textContent (nunca innerHTML): o log pode
// ter sido escrito por um atacante, então isso evita XSS na tela do analista.
(function () {
  "use strict";
  var INTERVALO = 2000;
  var PONTOS = 60; // 60 x 2 s = 2 minutos no gráfico
  var SEVERIDADES = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"];
  var CORES = { CRITICA: "#ff5c5c", ALTA: "#ff9f43", MEDIA: "#f6d55c", BAIXA: "#5dade2", INFO: "#8b98a5" };

  var historico = [];
  for (var i = 0; i < PONTOS; i++) historico.push(0);
  var ultimoTotal = null;
  var vistos = {};
  var primeiraCarga = true;
  var valores = {};

  function $(id) { return document.getElementById(id); }

  function el(tag, classe, texto) {
    var e = document.createElement(tag);
    if (classe) e.className = classe;
    if (texto !== undefined && texto !== null) e.textContent = String(texto);
    return e;
  }

  // Contador que "sobe" até o valor novo
  function animarNumero(id, alvo) {
    var noh = $(id);
    var inicio = valores[id] || 0;
    valores[id] = alvo;
    if (inicio === alvo) { noh.textContent = alvo; return; }
    noh.classList.remove("pulso"); void noh.offsetWidth; noh.classList.add("pulso");
    var t0 = performance.now();
    function passo(t) {
      var p = Math.min(1, (t - t0) / 700);
      noh.textContent = Math.round(inicio + (alvo - inicio) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(passo);
    }
    requestAnimationFrame(passo);
  }

  function desenharGrafico() {
    var c = $("grafico");
    var dpr = window.devicePixelRatio || 1;
    var w = c.clientWidth, h = 140;
    c.width = w * dpr; c.height = h * dpr;
    var ctx = c.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    var max = Math.max(4, Math.max.apply(null, historico));
    var largura = w / PONTOS;
    ctx.strokeStyle = "#263241"; ctx.lineWidth = 1;
    for (var g = 1; g <= 3; g++) {
      var y = h - (h - 16) * g / 3;
      ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
    }
    historico.forEach(function (v, i) {
      if (!v) return;
      var alt = (h - 16) * v / max;
      ctx.fillStyle = v >= max * 0.7 ? "#ff5c5c" : (v >= max * 0.35 ? "#ff9f43" : "#3fb6a8");
      ctx.fillRect(i * largura + 1, h - alt, Math.max(2, largura - 2), alt);
    });
    ctx.fillStyle = "#8b98a5"; ctx.font = "11px system-ui";
    ctx.fillText("pico: " + max + " alertas / 2 s", 6, 12);
  }

  function mostrarBanner(alerta) {
    $("banner-texto").textContent = (alerta.regra_nome || alerta.regra_id) + " — " + alerta.ip;
    var b = $("banner-critico");
    b.hidden = false;
    document.body.classList.remove("piscar"); void document.body.offsetWidth; document.body.classList.add("piscar");
    clearTimeout(mostrarBanner.t);
    mostrarBanner.t = setTimeout(function () { b.hidden = true; }, 4000);
  }

  function renderFeed(ultimos) {
    var feed = $("feed");
    if (!ultimos.length) return;
    feed.textContent = "";
    var criticoNovo = null;
    ultimos.forEach(function (a) {
      var novo = !vistos[a.id];
      vistos[a.id] = true;
      var li = el("li", "item-feed" + (novo && !primeiraCarga ? " novo" : ""));
      li.appendChild(el("span", "sev sev-" + String(a.severidade).toLowerCase(), a.severidade));
      var corpo = el("div", "corpo");
      var titulo = el("div", "titulo");
      titulo.appendChild(el("b", "", (a.regra_id || "") + " · " + (a.regra_nome || "")));
      corpo.appendChild(titulo);
      var linha = el("div", "meta");
      var link = el("a", "", a.ip);
      link.href = "/ip?ip=" + encodeURIComponent(a.ip || "");
      linha.appendChild(link);
      if (a.score_risco !== null && a.score_risco !== undefined) linha.appendChild(el("span", "", "  ·  risco ML " + a.score_risco));
      corpo.appendChild(linha);
      corpo.appendChild(el("div", "desc", a.descricao));
      li.appendChild(corpo);
      feed.appendChild(li);
      if (novo && !primeiraCarga && a.severidade === "CRITICA" && !criticoNovo) criticoNovo = a;
    });
    if (criticoNovo) mostrarBanner(criticoNovo);
  }

  function renderSeveridades(contagem) {
    var caixa = $("severidades");
    caixa.textContent = "";
    var max = 1;
    SEVERIDADES.forEach(function (s) { max = Math.max(max, contagem[s] || 0); });
    SEVERIDADES.forEach(function (s) {
      var linha = el("div", "barra-vivo");
      linha.appendChild(el("span", "sev sev-" + s.toLowerCase(), s));
      var trilho = el("div", "trilho");
      var preench = el("div", "preench");
      preench.style.width = (100 * (contagem[s] || 0) / max) + "%";
      preench.style.background = CORES[s];
      trilho.appendChild(preench);
      linha.appendChild(trilho);
      linha.appendChild(el("b", "", contagem[s] || 0));
      caixa.appendChild(linha);
    });
  }

  function renderRisco(lista) {
    var ul = $("risco");
    if (!lista.length) return;
    ul.textContent = "";
    lista.forEach(function (r) {
      var li = el("li");
      var link = el("a", "", r.ip);
      link.href = "/ip?ip=" + encodeURIComponent(r.ip || "");
      li.appendChild(link);
      var trilho = el("div", "trilho");
      var preench = el("div", "preench");
      var score = Number(r.score || 0);
      preench.style.width = score + "%";
      preench.style.background = score >= 85 ? CORES.CRITICA : score >= 65 ? CORES.ALTA : score >= 40 ? CORES.MEDIA : "#3fb6a8";
      trilho.appendChild(preench);
      li.appendChild(trilho);
      li.appendChild(el("b", "", r.score === null || r.score === undefined ? "—" : score.toFixed(1)));
      ul.appendChild(li);
    });
  }

  var ultimaSaude = "";
  function renderSaude(s) {
    if (!s) return;
    var assinatura = JSON.stringify(s);
    if (assinatura === ultimaSaude) return; // não redesenha (mantém aberto o "Por que essa nota?")
    ultimaSaude = assinatura;
    animarNumero("nota", s.nota);
    var cartao = $("saude");
    cartao.className = "cartao saude saude-" + s.classe;
    $("faixa").textContent = s.faixa;
    $("resumo-saude").textContent = s.resumo;
    var acoes = $("acoes-saude");
    acoes.textContent = "";
    if (!s.acoes.length) acoes.appendChild(el("li", "vazio", "Nada urgente agora. Continue acompanhando."));
    s.acoes.forEach(function (a) {
      var li = el("li");
      li.appendChild(el("b", "", a.titulo));
      li.appendChild(el("div", "meta", a.como));
      acoes.appendChild(li);
    });
    var desc = $("descontos-saude");
    desc.textContent = "";
    if (!s.descontos.length) desc.appendChild(el("li", "", "Nenhum ponto perdido."));
    s.descontos.forEach(function (d) { desc.appendChild(el("li", "", "−" + d.pontos + " pontos: " + d.motivo)); });
  }

  function atualizar() {
    fetch("/api/ao-vivo", { cache: "no-store", credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        var total = d.totais.alertas;
        var delta = ultimoTotal === null ? 0 : Math.max(0, total - ultimoTotal);
        if (total < (ultimoTotal || 0)) { vistos = {}; } // dados zerados
        ultimoTotal = total;
        historico.push(delta); historico.shift();
        animarNumero("n-eventos", d.totais.eventos);
        animarNumero("n-alertas", total);
        animarNumero("n-ips", d.totais.ips_pontuados);
        animarNumero("n-criticos", d.alertas_por_severidade.CRITICA || 0);
        renderFeed(d.ultimos);
        renderSeveridades(d.alertas_por_severidade);
        renderRisco(d.top_risco);
        renderSaude(d.saude);
        desenharGrafico();
        primeiraCarga = false;
        var s = $("status");
        s.textContent = "AO VIVO · atualizado " + new Date().toLocaleTimeString("pt-BR");
        s.className = "status ok";
      })
      .catch(function () {
        var s = $("status");
        s.textContent = "reconectando…";
        s.className = "status erro";
      });
  }

  window.addEventListener("resize", desenharGrafico);
  atualizar();
  setInterval(atualizar, INTERVALO);
})();
