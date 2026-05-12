from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import bcrypt
import os

app = FastAPI()

VAULT_ADDR  = os.getenv("VAULT_ADDR",      "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN",     "")
VAULT_NS    = os.getenv("VAULT_NAMESPACE", "admin/ibm")
VAULT_MOUNT = os.getenv("VAULT_MOUNT",     "secret")


def vault_headers():
    return {
        "X-Vault-Token":     VAULT_TOKEN,
        "X-Vault-Namespace": VAULT_NS,
        "Content-Type":      "application/json",
    }


def vault_url(user: str) -> str:
    return f"{VAULT_ADDR}/v1/{VAULT_MOUNT}/data/usuarios/{user}"


class UserPayload(BaseModel):
    user: str
    senha: str


@app.post("/register", status_code=201)
async def register(payload: UserPayload):
    url = vault_url(payload.user)
    print(f"[register] GET {url}", flush=True)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            check = await client.get(url, headers=vault_headers())
            print(f"[register] check status={check.status_code}", flush=True)

            if check.status_code == 200:
                raise HTTPException(status_code=409, detail="Usuário já existe")
            if check.status_code == 403:
                raise HTTPException(status_code=502, detail="Vault: acesso negado (403) — verifique VAULT_TOKEN e VAULT_NAMESPACE")
            if check.status_code != 404:
                raise HTTPException(status_code=502, detail=f"Vault retornou status inesperado: {check.status_code}")

            senha_hash = bcrypt.hashpw(payload.senha.encode(), bcrypt.gensalt()).decode()

            print(f"[register] POST {url}", flush=True)
            write = await client.post(
                url,
                headers=vault_headers(),
                json={"data": {"senha_hash": senha_hash}},
            )
            print(f"[register] write status={write.status_code}", flush=True)

            if write.status_code == 403:
                raise HTTPException(status_code=502, detail="Vault: acesso negado ao escrever (403) — verifique permissões do token")
            if write.status_code not in (200, 204):
                raise HTTPException(status_code=502, detail=f"Vault retornou status inesperado ao salvar: {write.status_code}")

    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao conectar no Vault")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro ao conectar no Vault: {exc}")

    return {"message": "Usuário cadastrado com sucesso", "user": payload.user}


@app.post("/login")
async def login(payload: UserPayload):
    url = vault_url(payload.user)
    print(f"[login] GET {url}", flush=True)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=vault_headers())
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao conectar no Vault")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro ao conectar no Vault: {exc}")

    print(f"[login] status={resp.status_code}", flush=True)

    if resp.status_code == 404:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail="Vault: acesso negado (403) — verifique VAULT_TOKEN e VAULT_NAMESPACE")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault retornou status inesperado: {resp.status_code}")

    vault_data = resp.json()
    senha_hash = vault_data.get("data", {}).get("data", {}).get("senha_hash")

    if not senha_hash:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not bcrypt.checkpw(payload.senha.encode(), senha_hash.encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    return {"message": "Login valido", "user": payload.user}


@app.get("/dados")
def dados():
    return {
        "mensagem": "Acesso autorizado",
        "dados": {"produto": "API Demo", "versao": "1.0"},
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/debug")
def debug():
    return {
        "VAULT_ADDR":  VAULT_ADDR,
        "VAULT_NS":    VAULT_NS,
        "VAULT_MOUNT": VAULT_MOUNT,
        "TOKEN_SET":   bool(VAULT_TOKEN),
    }
