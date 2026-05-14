#!/bin/bash
set -e

echo "=== VaultFone Backend — Cloud Run ==="

# ── Cria diretórios necessários ──────────────────────────────────
mkdir -p /vault/config /vault/secrets /vault/templates

# ── Busca role_id e secret_id do GCP Secret Manager ─────────────
echo "Buscando credenciais do Vault no Secret Manager..."

ROLE_ID=$(gcloud secrets versions access latest \
  --secret=vault-backend-role-id \
  --project=apigee-vault-demo-496023)

SECRET_ID=$(gcloud secrets versions access latest \
  --secret=vault-backend-secret-id \
  --project=apigee-vault-demo-496023)

echo "$ROLE_ID"   > /vault/config/role-id
echo "$SECRET_ID" > /vault/config/secret-id

echo "Credenciais carregadas."

# ── Copia template e config do Vault Agent ───────────────────────
cp /app/vault-agent/extrato-api-key.tpl /vault/templates/
cp /app/vault-agent/config.hcl          /vault/config/

# ── Inicia Vault Agent em background ────────────────────────────
echo "Iniciando Vault Agent..."
vault agent -config=/vault/config/config.hcl &
VAULT_AGENT_PID=$!

# ── Aguarda o Vault Agent escrever o secret ──────────────────────
echo "Aguardando Vault Agent renderizar secrets..."
TIMEOUT=30
ELAPSED=0
until [ -f /vault/secrets/extrato-api-key ] && [ -s /vault/secrets/extrato-api-key ]; do
  sleep 1
  ELAPSED=$((ELAPSED + 1))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERRO: Vault Agent não renderizou o secret em ${TIMEOUT}s"
    exit 1
  fi
done

echo "Secret disponível em /vault/secrets/extrato-api-key"

# ── Inicia o backend FastAPI ─────────────────────────────────────
echo "Iniciando backend FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8080
