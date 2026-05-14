#!/bin/bash
set -e

echo "=== VaultFone Backend — Cloud Run ==="

mkdir -p /vault/config /vault/secrets /vault/templates

# ── Busca token de acesso via metadata server ────────────────────
echo "Buscando token GCP..."
ACCESS_TOKEN=$(curl -s \
  -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# ── Busca secrets do Secret Manager via REST ─────────────────────
echo "Buscando credenciais do Vault no Secret Manager..."

ROLE_ID=$(curl -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/apigee-vault-demo-496023/secrets/vault-backend-role-id/versions/latest:access" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['payload']['data']).decode())")

SECRET_ID=$(curl -s \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/apigee-vault-demo-496023/secrets/vault-backend-secret-id/versions/latest:access" \
  | python3 -c "import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)['payload']['data']).decode())")

echo "$ROLE_ID"   > /vault/config/role-id
echo "$SECRET_ID" > /vault/config/secret-id

echo "Credenciais carregadas."

cp /app/vault-agent/extrato-api-key.tpl /vault/templates/
cp /app/vault-agent/ca-cert.tpl         /vault/templates/
cp /app/vault-agent/config.hcl          /vault/config/

echo "Iniciando Vault Agent..."
vault agent -config=/vault/config/config.hcl &

echo "Aguardando Vault Agent renderizar secrets..."
TIMEOUT=30
ELAPSED=0
until [ -f /vault/secrets/extrato-api-key ] && [ -s /vault/secrets/extrato-api-key ] && \
      [ -f /vault/secrets/ca.crt ]          && [ -s /vault/secrets/ca.crt ]; do
  sleep 1
  ELAPSED=$((ELAPSED + 1))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERRO: Vault Agent não renderizou os secrets em ${TIMEOUT}s"
    exit 1
  fi
done

echo "Secrets disponíveis."
echo "Iniciando backend FastAPI..."
exec uvicorn main:app --host 0.0.0.0 --port 8080