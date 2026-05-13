"""
routers/faturas_router.py
──────────────────────────────────────────────────────────────────────────────
CASO DE USO DEMO — Faturamento Telecom (VaultFone)

Demonstra:
  • Autenticação com credenciais armazenadas no Vault KV (kvapigee-demo)
  • Emissão de JWT via Transit Engine (chave privada nunca exposta)
  • Validação do JWT antes de retornar dados protegidos

Endpoints:
  POST /faturas/login              → autentica e retorna JWT (Transit sign)
  GET  /faturas/{cpf}              → lista faturas (requer Bearer JWT válido)
  GET  /faturas/{cpf}/{fatura_id}  → detalhe de fatura (requer Bearer JWT válido)

Variáveis de ambiente:
  VAULT_KV_DEMO   → mount do KV com usuários demo (default: "kvapigee-demo")
  SELF_BASE_URL   → URL base desta própria API para chamadas internas (default: "http://localhost:8080")
"""

import os
import bcrypt
import httpx
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from typing import Optional

from core.vault_client import vault_get

router = APIRouter()

VAULT_KV_DEMO = os.getenv("VAULT_KV_DEMO",  "kvapigee-demo")
SELF_BASE_URL = os.getenv("SELF_BASE_URL", "https://backend-demo-production-e92d.up.railway.app").rstrip("/")
print(f"[DEBUG] SELF_BASE_URL={SELF_BASE_URL!r}")


# ── mock de faturas por CPF ────────────────────────────────────────────────

_FATURAS = {
    "111.111.111-11": [
        {
            "id": "FAT-2025-05", "mes": 5, "ano": 2025,
            "vencimento": "2025-05-15", "valor": 79.90,
            "status": "aberta", "plano": "Prata 15GB",
            "itens": [
                {"descricao": "Plano Prata 15GB",      "valor": 69.90},
                {"descricao": "Dados adicionais 2 GB", "valor": 10.00},
            ],
        },
        {
            "id": "FAT-2025-04", "mes": 4, "ano": 2025,
            "vencimento": "2025-04-15", "valor": 69.90,
            "status": "paga", "plano": "Prata 15GB",
            "itens": [
                {"descricao": "Plano Prata 15GB", "valor": 69.90},
            ],
        },
        {
            "id": "FAT-2025-03", "mes": 3, "ano": 2025,
            "vencimento": "2025-03-15", "valor": 94.90,
            "status": "vencida", "plano": "Prata 15GB",
            "itens": [
                {"descricao": "Plano Prata 15GB",             "valor": 69.90},
                {"descricao": "Ligações excedentes (32 min)", "valor": 15.00},
                {"descricao": "Multa por atraso (2%)",        "valor": 10.00},
            ],
        },
    ],
    "222.222.222-22": [
        {
            "id": "FAT-2025-05", "mes": 5, "ano": 2025,
            "vencimento": "2025-05-20", "valor": 119.90,
            "status": "aberta", "plano": "Ouro 30GB",
            "itens": [
                {"descricao": "Plano Ouro 30GB",                "valor":  99.90},
                {"descricao": "Roaming internacional (3 dias)", "valor":  20.00},
            ],
        },
        {
            "id": "FAT-2025-04", "mes": 4, "ano": 2025,
            "vencimento": "2025-04-20", "valor": 99.90,
            "status": "paga", "plano": "Ouro 30GB",
            "itens": [
                {"descricao": "Plano Ouro 30GB", "valor": 99.90},
            ],
        },
        {
            "id": "FAT-2025-03", "mes": 3, "ano": 2025,
            "vencimento": "2025-03-20", "valor": 111.90,
            "status": "vencida", "plano": "Ouro 30GB",
            "itens": [
                {"descricao": "Plano Ouro 30GB",       "valor": 99.90},
                {"descricao": "Dados adicionais 5 GB", "valor": 10.00},
                {"descricao": "Multa por atraso (2%)", "valor":  2.00},
            ],
        },
    ],
}


# ── helpers internos ───────────────────────────────────────────────────────

async def _sign_jwt(claims: dict) -> str:
    """Chama POST /transit/sign e retorna o JWT assinado."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(f"{SELF_BASE_URL}/transit/sign", json={"claims": claims})
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout ao assinar JWT via Transit Engine")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Erro ao assinar JWT: {exc}")
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Transit Engine não retornou JWT")
    return resp.json()["jwt"]


async def _verify_jwt(token: str) -> dict:
    import base64 as _b64, json as _json
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=401, detail="Token inválido")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{SELF_BASE_URL}/transit/verify",
                json={"jwt": token},
                headers={"Content-Type": "application/json"},
            )

        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Token inválido")

        data = resp.json()
        if not data.get("valid"):
            raise HTTPException(status_code=401, detail="Token inválido")

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        payload = _json.loads(_b64.urlsafe_b64decode(payload_b64 + "=" * padding))
        return payload

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Erro ao verificar JWT: {exc}")


def _extract_bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente — use Authorization: Bearer <token>")
    return authorization[7:]


# ── modelos ────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    cpf: str
    senha: str


# ── endpoints ──────────────────────────────────────────────────────────────

@router.post("/login", summary="Autentica usuário VaultFone e retorna JWT (Transit Engine)")
async def login(req: LoginRequest):
    """
    Busca o usuário no Vault KV, valida a senha com bcrypt e emite JWT
    assinado pelo Transit Engine. A chave privada nunca sai do Vault.
    """
    path = f"{VAULT_KV_DEMO}/data/usuarios/{req.cpf}"

    try:
        vault_data = await vault_get(path)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
        raise

    stored     = vault_data.get("data", {}).get("data", {})
    senha_hash = stored.get("senha_hash", "")
    nome       = stored.get("nome", "")

    if not senha_hash or not bcrypt.checkpw(req.senha.encode(), senha_hash.encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    claims = {
        "sub":  req.cpf,
        "iss":  "apigee-vault-demo",
        "aud":  "faturas-backend",
        "nome": nome,
    }
    token = await _sign_jwt(claims)

    return {"token": token, "nome": nome, "cpf": req.cpf}


@router.get("/{cpf}", summary="Lista faturas VaultFone do CPF (requer Bearer JWT)")
async def list_faturas(cpf: str, authorization: Optional[str] = Header(None)):
    """
    Valida o JWT via Transit Engine e retorna o resumo das 3 faturas mais recentes.
    Itens detalhados disponíveis em GET /faturas/{cpf}/{fatura_id}.
    """
    token  = _extract_bearer(authorization)
    claims = await _verify_jwt(token)

    if claims.get("sub") != cpf:
        raise HTTPException(status_code=403, detail="Token não pertence a este CPF")

    faturas = _FATURAS.get(cpf)
    if faturas is None:
        raise HTTPException(status_code=404, detail=f"Nenhuma fatura encontrada para CPF {cpf}")

    resumo = [{k: v for k, v in f.items() if k != "itens"} for f in faturas]

    return {
        "operadora": "VaultFone",
        "cpf":       cpf,
        "nome":      claims.get("nome", ""),
        "faturas":   resumo,
    }


@router.get("/{cpf}/{fatura_id}", summary="Detalhe de fatura VaultFone (requer Bearer JWT)")
async def get_fatura(cpf: str, fatura_id: str, authorization: Optional[str] = Header(None)):
    """
    Valida o JWT via Transit Engine e retorna a fatura completa com itens de cobrança.
    Faturas vencidas incluem multa por atraso nos itens.
    """
    token  = _extract_bearer(authorization)
    claims = await _verify_jwt(token)

    if claims.get("sub") != cpf:
        raise HTTPException(status_code=403, detail="Token não pertence a este CPF")

    faturas = _FATURAS.get(cpf)
    if faturas is None:
        raise HTTPException(status_code=404, detail=f"Nenhuma fatura encontrada para CPF {cpf}")

    fatura = next((f for f in faturas if f["id"] == fatura_id), None)
    if fatura is None:
        raise HTTPException(status_code=404, detail=f"Fatura {fatura_id} não encontrada")

    return {
        "operadora": "VaultFone",
        "cpf":       cpf,
        "nome":      claims.get("nome", ""),
        "fatura":    fatura,
    }
