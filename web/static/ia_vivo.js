// Botão "Analisar com IA" da tela Ao vivo: pede o boletim e "digita" o texto na tela.
(function () {
  "use strict";
  var form = document.getElementById("form-ia");
  if (!form) return;
  var botao = document.getElementById("botao-ia");
  var caixa = document.getElementById("texto-ia");
  var origem = document.getElementById("origem-ia");
  var digitando = null;
  var blocoIndicios = document.getElementById("indicios-ia");
  var listaIndicios = document.getElementById("lista-indicios");

  function mostrarIndicios(indicios) {
    listaIndicios.textContent = "";
    if (!indicios || !indicios.length) { blocoIndicios.hidden = true; return; }
    indicios.forEach(function (ind) {
      var titulo = document.createElement("p");
      titulo.className = "ind-ip " + (ind.possivel_sucesso ? "ind-alerta" : "ind-ok");
      titulo.textContent = ind.ip + " — " + (ind.possivel_sucesso
        ? "há sinais de que algum ataque pode ter funcionado"
        : "nenhum sinal de sucesso nos registros");
      listaIndicios.appendChild(titulo);
      var ul = document.createElement("ul");
      ind.indicios.forEach(function (frase) {
        var li = document.createElement("li");
        li.textContent = frase;
        ul.appendChild(li);
      });
      listaIndicios.appendChild(ul);
    });
    blocoIndicios.hidden = false;
  }

  function digitar(texto) {
    clearInterval(digitando);
    caixa.textContent = "";
    caixa.classList.remove("vazio");
    var i = 0;
    digitando = setInterval(function () {
      i += 2;
      caixa.textContent = texto.slice(0, i);
      if (i >= texto.length) clearInterval(digitando);
    }, 18);
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    botao.disabled = true;
    botao.textContent = "Analisando…";
    caixa.classList.add("pensando");
    caixa.textContent = "A IA está lendo os alertas do momento…";
    origem.textContent = "";
    fetch("/ao-vivo/ia", { method: "POST", body: new FormData(form), credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        caixa.classList.remove("pensando");
        digitar(d.texto);
        mostrarIndicios(d.indicios);
        var nomes = { llm: "escrito pelo Gemini", mock: "modo sem IA (regras)", fallback: "Gemini indisponível — boletim por regras" };
        origem.textContent = "origem: " + (nomes[d.origem] || d.origem) + " · " + new Date().toLocaleTimeString("pt-BR");
      })
      .catch(function () {
        caixa.classList.remove("pensando");
        caixa.textContent = "Não consegui gerar o boletim agora. Tente de novo em alguns segundos.";
      })
      .then(function () { botao.disabled = false; botao.textContent = "Analisar com IA"; });
  });
})();
