// Chat "Pergunte ao SecuraPy". Respostas escritas com textContent (sem HTML).
(function () {
  "use strict";
  var form = document.getElementById("form-chat");
  var campo = document.getElementById("pergunta");
  var botao = document.getElementById("enviar-chat");
  var conversa = document.getElementById("conversa");
  var historico = [];
  var nomes = { llm: "Gemini", mock: "respostas prontas (IA desligada)", fallback: "Gemini indisponível — resposta pronta" };

  function bolha(classe, texto) {
    var div = document.createElement("div");
    div.className = "msg " + classe;
    div.textContent = texto;
    conversa.appendChild(div);
    conversa.scrollTop = conversa.scrollHeight;
    return div;
  }

  function perguntar(texto) {
    texto = texto.trim();
    if (!texto || botao.disabled) return;
    bolha("voce", texto);
    var esperando = bolha("ia digitando", "pensando…");
    var dados = new FormData(form);
    dados.set("pergunta", texto);
    dados.set("historico", JSON.stringify(historico));
    campo.value = "";
    botao.disabled = true;
    fetch("/assistente/perguntar", { method: "POST", body: dados, credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        esperando.className = "msg ia";
        esperando.textContent = d.resposta;
        var origem = document.createElement("small");
        origem.className = "origem-msg";
        origem.textContent = "origem: " + (nomes[d.origem] || d.origem);
        esperando.appendChild(origem);
        historico.push({ de: "voce", texto: texto }, { de: "ia", texto: d.resposta });
        historico = historico.slice(-4);
      })
      .catch(function () {
        esperando.className = "msg ia erro";
        esperando.textContent = "Não consegui responder agora. Tente de novo em alguns segundos.";
      })
      .then(function () { botao.disabled = false; campo.focus(); conversa.scrollTop = conversa.scrollHeight; });
  }

  form.addEventListener("submit", function (ev) { ev.preventDefault(); perguntar(campo.value); });
  document.querySelectorAll("button.sugestao").forEach(function (b) {
    b.addEventListener("click", function () { perguntar(b.textContent); });
  });
})();
