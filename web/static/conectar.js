// Botões "Copiar" da página Conectar.
(function () {
  "use strict";
  document.querySelectorAll("button.copiar").forEach(function (botao) {
    botao.addEventListener("click", function () {
      var texto = document.getElementById(botao.getAttribute("data-alvo")).textContent;
      var pronto = function () {
        botao.textContent = "Copiado ✓";
        setTimeout(function () { botao.textContent = "Copiar comandos"; }, 2000);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(texto).then(pronto);
      } else { // http sem HTTPS: seleciona o texto para Ctrl+C
        var faixa = document.createRange();
        faixa.selectNodeContents(document.getElementById(botao.getAttribute("data-alvo")));
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(faixa);
        botao.textContent = "Selecionado — aperte Ctrl+C";
      }
    });
  });
})();
