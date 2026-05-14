FROM python:3.12-slim

# ── Instala dependências do sistema ─────────────────────────────
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Instala gcloud CLI ───────────────────────────────────────────
RUN curl -sSL https://sdk.cloud.google.com | bash -s -- --disable-prompts
ENV PATH="/root/google-cloud-sdk/bin:${PATH}"

# ── Instala Vault CLI (para o Vault Agent) ───────────────────────
ENV VAULT_VERSION=1.17.2
RUN curl -fsSL "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" -o /tmp/vault.zip \
    && unzip /tmp/vault.zip -d /usr/local/bin/ \
    && rm /tmp/vault.zip \
    && vault --version

WORKDIR /app

# ── Instala dependências Python ──────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copia código do backend ──────────────────────────────────────
COPY . .

# ── Copia arquivos do Vault Agent ────────────────────────────────
COPY vault-agent/ /app/vault-agent/

# ── Copia e configura script de inicialização ────────────────────
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8080

CMD ["/app/start.sh"]
