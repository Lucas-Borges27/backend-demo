from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import bcrypt
import os

app = FastAPI()

VAULT_ADDR      = os.getenv("VAULT_ADDR",      "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200")
VAULT_NS        = os.getenv("VAULT_NAMESPACE", "admin/ibm")
VAULT_MOUNT     = os.getenv("VAULT_MOUNT",     "secret")
VAULT_ROLE_ID   = os.getenv("VAULT_ROLE_ID",   "")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID", "")


async def get_vault_token() -> str:
    login_url = f"{VAULT_ADDR}/v1/auth/approle/login"
    print(f"[approle] POST {login_url}", flush=True)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                login_url,
                headers={"X-Vault-Namespace": VAULT_NS, "Content-Type": "application/json"},
                json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
            )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao autenticar no Vault (AppRole)")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro ao autenticar no Vault (AppRole): {exc}")

    print(f"[approle] status={resp.status_code}", flush=True)

    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail="Vault: AppRole negado (403) — verifique VAULT_ROLE_ID e VAULT_SECRET_ID")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault AppRole retornou status inesperado: {resp.status_code}")

    token = resp.json().get("auth", {}).get("client_token")
    if not token:
        raise HTTPException(status_code=502, detail="Vault: client_token ausente na resposta AppRole")
    return token


async def get_vault_headers() -> dict:
    token = await get_vault_token()
    return {
        "X-Vault-Token":     token,
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
        headers = await get_vault_headers()
        async with httpx.AsyncClient(timeout=10.0) as client:
            check = await client.get(url, headers=headers)
            print(f"[register] check status={check.status_code}", flush=True)

            if check.status_code == 200:
                raise HTTPException(status_code=409, detail="Usuário já existe")
            if check.status_code == 403:
                raise HTTPException(status_code=502, detail="Vault: acesso negado (403) — verifique permissões do AppRole")
            if check.status_code != 404:
                raise HTTPException(status_code=502, detail=f"Vault retornou status inesperado: {check.status_code}")

            senha_hash = bcrypt.hashpw(payload.senha.encode(), bcrypt.gensalt()).decode()

            print(f"[register] POST {url}", flush=True)
            write = await client.post(
                url,
                headers=headers,
                json={"data": {"senha_hash": senha_hash}},
            )
            print(f"[register] write status={write.status_code}", flush=True)

            if write.status_code == 403:
                raise HTTPException(status_code=502, detail="Vault: acesso negado ao escrever (403) — verifique permissões do AppRole")
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
        headers = await get_vault_headers()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao conectar no Vault")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro ao conectar no Vault: {exc}")

    print(f"[login] status={resp.status_code}", flush=True)

    if resp.status_code == 404:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail="Vault: acesso negado (403) — verifique permissões do AppRole")
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
        "VAULT_ADDR":    VAULT_ADDR,
        "VAULT_NS":      VAULT_NS,
        "VAULT_MOUNT":   VAULT_MOUNT,
        "ROLE_ID_SET":   bool(VAULT_ROLE_ID),
        "SECRET_ID_SET": bool(VAULT_SECRET_ID),
    }
