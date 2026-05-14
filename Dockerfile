FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV VAULT_VERSION=1.17.2
RUN curl -fsSL "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_amd64.zip" -o /tmp/vault.zip \
    && unzip /tmp/vault.zip -d /usr/local/bin/ \
    && rm /tmp/vault.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY vault-agent/ /app/vault-agent/
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 8080
CMD ["/app/start.sh"]