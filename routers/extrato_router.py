"""
routers/extrato_router.py
──────────────────────────────────────────────────────────────────────────────
CENÁRIO d — Credenciais de Target Server via Vault (sem Agent)

Variação sem Vault Agent:
  O Cloud Run autentica no Vault via JWT do metadata server GCP
  (sem SA key estática) e mantém a API key em cache em memória com TTL.
  Se a key for rejeitada, invalida o cache e busca novamente antes de
  retornar erro — garante funcionamento após rotação da key no Vault.
  Nada em disco, nenhum Agent, nenhuma credencial estática.

  Fluxo:
    GET metadata server (audience=https://vault.hashicorp.com) → oidc_token
    POST /v1/auth/jwt/login {role, jwt} → client_token
    GET /v1/kvapigee-demo/data/extrato-api-key → api_key

Variáveis de ambiente:
  EXTRATO_API_KEY         → fallback dev local
  EXTRATO_KEY_TTL_SECONDS → TTL do cache da key em segundos (default: 3600)
"""

import os
import time
from threading import Lock

import httpx
from fastapi import APIRouter, Header, HTTPException
from typing import Annotated

router = APIRouter()

VAULT_BASE_URL     = "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200"
VAULT_NAMESPACE    = "admin/ibm"
VAULT_JWT_ROLE     = "apigee-gcp-role"
VAULT_SECRET_PATH  = "kvapigee-demo/data/extrato-api-key"
VAULT_JWT_AUD      = "https://vault.hashicorp.com"
METADATA_TOKEN_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
    f"?audience={VAULT_JWT_AUD}&format=full"
)
EXTRATO_KEY_TTL    = int(os.getenv("EXTRATO_KEY_TTL_SECONDS", "3600"))


# ── cache em memória ───────────────────────────────────────────────────────

_key_cache: dict = {"key": None, "fetched_at": 0.0}
_key_lock  = Lock()


def _get_gcp_oidc_token() -> str:
    try:
        resp = httpx.get(
            METADATA_TOKEN_URL,
            headers={"Metadata-Flavor": "Google"},
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.text.strip()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Falha ao obter token GCP do metadata server: {e}")


def _get_vault_token(oidc_token: str) -> str:
    try:
        resp = httpx.post(
            f"{VAULT_BASE_URL}/v1/auth/jwt/login",
            headers={"X-Vault-Namespace": VAULT_NAMESPACE},
            json={"role": VAULT_JWT_ROLE, "jwt": oidc_token},
            timeout=5.0,
        )
        resp.raise_for_status()
        return resp.json()["auth"]["client_token"]
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Falha ao autenticar no Vault via JWT: {e}")
    except (KeyError, TypeError):
        raise HTTPException(status_code=503, detail="Vault JWT login não retornou client_token")


def _fetch_key_from_vault() -> str:
    oidc_token  = _get_gcp_oidc_token()
    vault_token = _get_vault_token(oidc_token)

    try:
        resp = httpx.get(
            f"{VAULT_BASE_URL}/v1/{VAULT_SECRET_PATH}",
            headers={
                "X-Vault-Namespace": VAULT_NAMESPACE,
                "X-Vault-Token":     vault_token,
            },
            timeout=5.0,
        )
        resp.raise_for_status()
        key = resp.json()["data"]["data"]["api_key"]
        if not key:
            raise HTTPException(status_code=503, detail="Vault retornou api_key vazia")
        return key
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Falha ao ler secret do Vault: {e}")
    except (KeyError, TypeError):
        raise HTTPException(status_code=503, detail="Campo api_key não encontrado no secret do Vault")


def _load_api_key() -> str:
    """
    Retorna a API key do cache em memória.
    Renova via Vault se o TTL expirou.
    Thread-safe via Lock.
    """
    now = time.monotonic()
    with _key_lock:
        if _key_cache["key"] is None or (now - _key_cache["fetched_at"]) > EXTRATO_KEY_TTL:
            _key_cache["key"]        = _fetch_key_from_vault()
            _key_cache["fetched_at"] = now
    return _key_cache["key"]


def _invalidate_key_cache() -> None:
    """Força renovação da key no próximo _load_api_key()."""
    with _key_lock:
        _key_cache["fetched_at"] = 0.0


# ── dados de extrato (seed para demo) ─────────────────────────────────────

_EXTRATO = {
    "111.111.111-11": {
        "nome": "João Silva",
        "plano": "Prata 15GB",
        "ciclo": "mai/2025",
        "consumo": {
            "dados_utilizados_gb": 11.4,
            "dados_total_gb": 15.0,
            "dados_restantes_gb": 3.6,
            "ligacoes_minutos": 182,
            "sms_enviados": 14,
        },
        "alertas": [
            {"tipo": "dados", "mensagem": "Você já usou 76% do seu pacote de dados."},
        ],
    },
    "222.222.222-22": {
        "nome": "Maria Santos",
        "plano": "Ouro 30GB",
        "ciclo": "mai/2025",
        "consumo": {
            "dados_utilizados_gb": 8.2,
            "dados_total_gb": 30.0,
            "dados_restantes_gb": 21.8,
            "ligacoes_minutos": 45,
            "sms_enviados": 3,
        },
        "alertas": [],
    },
}


# ── endpoint ───────────────────────────────────────────────────────────────

@router.get("/{cpf}", summary="Extrato de consumo — protegido por x-api-key via Vault (sem Agent)")
async def get_extrato(
    cpf: str,
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
):
    # fallback dev local
    expected_key = os.getenv("EXTRATO_API_KEY", "").strip() or _load_api_key()

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Serviço indisponível — key não disponível",
        )

    if not x_api_key or x_api_key != expected_key:
        # key pode ter rotacionado — invalida cache e retenta uma vez
        _invalidate_key_cache()
        expected_key = os.getenv("EXTRATO_API_KEY", "").strip() or _load_api_key()
        if not x_api_key or x_api_key != expected_key:
            raise HTTPException(
                status_code=401,
                detail="x-api-key ausente ou inválida",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    extrato = _EXTRATO.get(cpf)
    if extrato is None:
        raise HTTPException(status_code=404, detail=f"Nenhum extrato encontrado para CPF {cpf}")

    key_age_seconds = int(time.monotonic() - _key_cache["fetched_at"])

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        **extrato,
        "_meta": {
            "auth_method":           "x-api-key via Vault JWT (sem Agent)",
            "key_source":            f"{VAULT_BASE_URL}/v1/{VAULT_SECRET_PATH}",
            "vault_auth":            f"jwt/role/{VAULT_JWT_ROLE}",
            "key_cache_age_seconds": key_age_seconds,
            "key_ttl_seconds":       EXTRATO_KEY_TTL,
            "hardcoded_in_apigee":   False,
            "hardcoded_in_backend":  False,
        },
    }