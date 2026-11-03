# SecuraPy Platform — imagem da API (Flask + gunicorn) — Aula 11
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependências primeiro (camada em cache enquanto o requirements não muda)
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Usuário sem privilégios: se a aplicação for comprometida, não é root no contêiner
RUN useradd --create-home --uid 10001 securapy \
    && mkdir -p /app/var /app/saida \
    && chown -R securapy:securapy /app/var /app/saida
USER securapy

# 5000 = API/dashboard · 9999 = servidor TCP de alertas em tempo real
EXPOSE 5000 9999

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/saude', timeout=4).status == 200 else 1)"

# 1 worker: o servidor TCP de alertas roda dentro do processo da API
# (vários workers tentariam abrir a porta 9999 ao mesmo tempo). Threads atendem a concorrência.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--bind", "0.0.0.0:5000", "--access-logfile", "-", "api.app:create_app()"]
