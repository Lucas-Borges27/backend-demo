"""
core/vault_client.py
──────────────────────────────────────────────────────────────────────────────
Cliente centralizado para o HashiCorp Vault.
Todos os routers importam daqui — nenhum router faz AppRole login diretamente.

Funcionalidades:
  • get_vault_token()   — AppRole login, retorna client_token
  • get_vault_headers() — headers prontos para qualquer chamada
  • vault_get()         — GET genérico com tratamento de erros
  • vault_post()        — POST genérico com tratamento de erros
  • vault_put()         — PUT genérico com tratamento de erros
"""

import os
import httpx
from fastapi import HTTPException

# ── configuração via env ───────────────────────────────────────────────────
VAULT_ADDR      = os.getenv("VAULT_ADDR",      "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200")
VAULT_NS        = os.getenv("VAULT_NAMESPACE", "admin/ibm")
VAULT_MOUNT     = os.getenv("VAULT_MOUNT",     "secret")
VAULT_ROLE_ID   = os.getenv("VAULT_ROLE_ID",   "")
VAULT_SECRET_ID = os.getenv("VAULT_SECRET_ID", "")

# mounts dedicados (podem ser sobrescritos por env)
VAULT_TRANSIT_MOUNT = os.getenv("VAULT_TRANSIT_MOUNT", "transit")
VAULT_PKI_MOUNT     = os.getenv("VAULT_PKI_MOUNT",     "pki")


# ── autenticação ───────────────────────────────────────────────────────────
async def get_vault_token() -> str:
    """Faz login via AppRole e retorna o client_token."""
    login_url = f"{VAULT_ADDR}/v1/auth/approle/login"
    print(f"[vault] AppRole login → {login_url}", flush=True)
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
        raise HTTPException(status_code=502, detail=f"Erro ao autenticar no Vault: {exc}")

    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail="Vault: AppRole negado (403) — verifique ROLE_ID/SECRET_ID")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault AppRole status inesperado: {resp.status_code}")

    token = resp.json().get("auth", {}).get("client_token")
    if not token:
        raise HTTPException(status_code=502, detail="Vault: client_token ausente na resposta AppRole")

    print(f"[vault] token obtido (prefixo: {token[:8]}...)", flush=True)
    return token


async def get_vault_headers() -> dict:
    """Retorna headers prontos: token + namespace + content-type."""
    token = await get_vault_token()
    return {
        "X-Vault-Token":     token,
        "X-Vault-Namespace": VAULT_NS,
        "Content-Type":      "application/json",
    }


# ── helpers HTTP genéricos ─────────────────────────────────────────────────
async def vault_get(path: str) -> dict:
    """
    GET {VAULT_ADDR}/v1/{path}
    Retorna resp.json() ou lança HTTPException.
    """
    url = f"{VAULT_ADDR}/v1/{path}"
    print(f"[vault] GET {url}", flush=True)
    try:
        headers = await get_vault_headers()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url, headers=headers)
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Timeout: GET {path}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro: GET {path}: {exc}")

    print(f"[vault] GET {path} → {resp.status_code}", flush=True)

    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"Segredo não encontrado: {path}")
    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail=f"Vault: acesso negado a {path}")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault status inesperado {resp.status_code}: {path}")

    return resp.json()


async def vault_post(path: str, payload: dict) -> dict:
    """
    POST {VAULT_ADDR}/v1/{path}
    Retorna resp.json() ou lança HTTPException.
    """
    url = f"{VAULT_ADDR}/v1/{path}"
    print(f"[vault] POST {url}", flush=True)
    try:
        headers = await get_vault_headers()
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Timeout: POST {path}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro: POST {path}: {exc}")

    print(f"[vault] POST {path} → {resp.status_code}", flush=True)

    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail=f"Vault: acesso negado a {path}")
    if resp.status_code not in (200, 201, 204):
        raise HTTPException(status_code=502, detail=f"Vault status inesperado {resp.status_code}: {path}")

    return resp.json() if resp.content else {}


async def vault_put(path: str, payload: dict) -> dict:
    """PUT genérico — usado para atualizar segredos KV."""
    url = f"{VAULT_ADDR}/v1/{path}"
    print(f"[vault] PUT {url}", flush=True)
    try:
        headers = await get_vault_headers()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(url, headers=headers, json=payload)
    except HTTPException:
        raise
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail=f"Timeout: PUT {path}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro: PUT {path}: {exc}")

    if resp.status_code == 403:
        raise HTTPException(status_code=502, detail=f"Vault: acesso negado a {path}")
    if resp.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail=f"Vault status inesperado {resp.status_code}: {path}")

    return resp.json() if resp.content else {}
