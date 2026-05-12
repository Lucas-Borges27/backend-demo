from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets
import httpx
import bcrypt
import os

app = FastAPI()
security = HTTPBasic()

# ── Vault config ──────────────────────────────────────────────
VAULT_ADDR     = os.getenv("VAULT_ADDR", "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200")
VAULT_TOKEN    = os.getenv("VAULT_TOKEN", "")
VAULT_NS       = os.getenv("VAULT_NAMESPACE", "admin/ibm")
VAULT_MOUNT    = os.getenv("VAULT_MOUNT", "secret")

def vault_headers():
    return {
        "X-Vault-Token":     VAULT_TOKEN,
        "X-Vault-Namespace": VAULT_NS,
        "Content-Type":      "application/json",
    }

def vault_url(user: str) -> str:
    # KV v2: /v1/{mount}/data/{path}
    return f"{VAULT_ADDR}/v1/{VAULT_MOUNT}/data/usuarios/{user}"

# ── Schemas ───────────────────────────────────────────────────
class UserPayload(BaseModel):
    user: str
    senha: str

# ── POST /register ────────────────────────────────────────────
@app.post("/register", status_code=201)
async def register(payload: UserPayload):
    # Verifica se usuário já existe
    async with httpx.AsyncClient() as client:
        check = await client.get(vault_url(payload.user), headers=vault_headers())
        if check.status_code == 200:
            raise HTTPException(status_code=409, detail="Usuário já existe")
        if check.status_code not in (200, 404):
            raise HTTPException(status_code=502, detail="Erro ao consultar Vault")

        # Hash da senha
        senha_hash = bcrypt.hashpw(
            payload.senha.encode(), bcrypt.gensalt()
        ).decode()

        # Salva no Vault (KV v2 exige { data: { ... } })
        write = await client.post(
            vault_url(payload.user),
            headers=vault_headers(),
            json={"data": {"senha_hash": senha_hash}},
        )

        if write.status_code not in (200, 204):
            raise HTTPException(status_code=502, detail="Erro ao salvar no Vault")

    return {"message": "Usuário cadastrado com sucesso", "user": payload.user}

# ── POST /login ───────────────────────────────────────────────
@app.post("/login")
async def login(payload: UserPayload):
    async with httpx.AsyncClient() as client:
        resp = await client.get(vault_url(payload.user), headers=vault_headers())

        if resp.status_code == 404:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Erro ao consultar Vault")

        vault_data = resp.json()
        senha_hash = vault_data.get("data", {}).get("data", {}).get("senha_hash")

        if not senha_hash:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")

        # Compara senha com hash
        valido = bcrypt.checkpw(payload.senha.encode(), senha_hash.encode())
        if not valido:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")

    # 200 → Apigee vai capturar e emitir o JWT
    return {"message": "Login válido", "user": payload.user}

# ── GET /dados ────────────────────────────────────────────────
# Chegará aqui somente após VerifyJWT no Apigee
# Apigee injeta o usuário via header X-User
@app.get("/dados")
def dados(request_user: str = None):
    from fastapi import Request
    return {
        "mensagem": "Acesso autorizado",
        "dados": {"produto": "API Demo", "versao": "1.0"}
    }

# ── GET /health ───────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}
