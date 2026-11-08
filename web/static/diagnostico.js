// Botão "Diagnosticar com IA" da página do IP: mostra problema, onde e correção.
(function () {
  "use strict";
  var form = document.getElementById("form-diag");
  if (!form) return;
  var botao = document.getElementById("botao-diag");
  var lista = document.getElementById("lista-diag");
  var origem = document.getElementById("origem-diag");

  function el(tag, classe, texto) {
    var e = document.createElement(tag);
    if (classe) e.className = classe;
    if (texto !== undefined) e.textContent = texto;
    return e;
  }

  function linha(rotulo, texto, classe) {
    var p = el("p", classe);
    p.appendChild(el("b", "", rotulo + " "));
    p.appendChild(el("span", "", texto));
    return p;
  }

  form.addEventListener("submit", function (ev) {
    ev.preventDefault();
    botao.disabled = true;
    botao.textContent = "Analisando…";
    lista.textContent = "";
    lista.appendChild(el("li", "vazio pensando", "A IA está examinando os ataques deste IP…"));
    origem.textContent = "";
    fetch("/ip/diagnostico", { method: "POST", body: new FormData(form), credentials: "same-origin" })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (d) {
        lista.textContent = "";
        if (!d.itens.length) {
          lista.appendChild(el("li", "vazio", "Nenhuma falha explorada por este IP — parece tráfego normal."));
        }
        d.itens.forEach(function (item, i) {
          var li = el("li", "item-diag");
          li.style.animationDelay = (i * 0.15) + "s";
          li.appendChild(linha("⚠️ Problema:", item.problema, "problema"));
          li.appendChild(linha("📍 Onde:", item.onde, "onde"));
          li.appendChild(linha("✅ Como corrigir:", item.correcao, "correcao"));
          lista.appendChild(li);
        });
        var nomes = { llm: "diagnóstico do Gemini", mock: "manual de correções (sem IA)",
                      fallback: "Gemini indisponível — manual de correções", sem_dados: "sem alertas" };
        origem.textContent = "origem: " + (nomes[d.origem] || d.origem);
      })
      .catch(function () {
        lista.textContent = "";
        lista.appendChild(el("li", "vazio", "Não consegui gerar o diagnóstico agora. Tente de novo."));
      })
      .then(function () { botao.disabled = false; botao.textContent = "Diagnosticar com IA"; });
  });
})();
