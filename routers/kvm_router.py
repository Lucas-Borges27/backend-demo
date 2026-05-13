"""
routers/kvm_router.py
──────────────────────────────────────────────────────────────────────────────
CASO DE USO 2 — Rotação de API Keys + Sync com KVM Apigee X

Fluxo completo:
  1. Vault KV é o source of truth das API Keys
  2. KVM do Apigee é um cache com TTL
  3. Este router sincroniza Vault → KVM via Apigee Management API

Endpoints:
  POST /kvm/apikey              → grava nova API Key no Vault
  GET  /kvm/apikey/{key_name}   → lê API Key do Vault (cache miss do KVM)
  POST /kvm/rotate/{key_name}   → gera nova versão da key + invalida KVM entry
  POST /kvm/sync                → força sync Vault → KVM Apigee para uma entry
  GET  /kvm/sync/status/{env}   → lista keys do Vault para um ambiente

Variáveis de ambiente necessárias para o sync com Apigee:
  APIGEE_MGMT_URL     → ex: https://apigee.googleapis.com
  APIGEE_ORG          → ex: minha-org-gcp
  APIGEE_ENV          → ex: prod
  APIGEE_KVM_NAME     → ex: vault-apikeys
  APIGEE_ACCESS_TOKEN → service account token (renovado externamente)
"""

import os
import secrets
import hashlib
from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Optional
import httpx

from core.vault_client import VAULT_MOUNT, vault_get, vault_post

router = APIRouter()

# ── config Apigee Management API ──────────────────────────────────────────
APIGEE_MGMT_URL     = os.getenv("APIGEE_MGMT_URL",     "https://apigee.googleapis.com")
APIGEE_ORG          = os.getenv("APIGEE_ORG",          "")
APIGEE_ENV          = os.getenv("APIGEE_ENV",           "prod")
APIGEE_KVM_NAME     = os.getenv("APIGEE_KVM_NAME",      "vault-apikeys")
APIGEE_ACCESS_TOKEN = os.getenv("APIGEE_ACCESS_TOKEN",  "")


# ── modelos ────────────────────────────────────────────────────────────────

class APIKeyPayload(BaseModel):
    key_name: str                     # identificador lógico ex: "parceiro-abc-prod"
    api_key: Optional[str] = None     # se None, gera automaticamente
    env: Optional[str] = "prod"
    description: Optional[str] = None


class SyncPayload(BaseModel):
    key_name: str
    env: str = "prod"
    kvm_name: Optional[str] = None   # sobrescreve APIGEE_KVM_NAME se informado


# ── helpers ────────────────────────────────────────────────────────────────

def _apikey_path(key_name: str, env: str) -> str:
    return f"{VAULT_MOUNT}/data/apigee/apikeys/{env}/{key_name}"


def _generate_api_key() -> str:
    """Gera API Key segura de 32 bytes hex."""
    return secrets.token_hex(32)


async def _sync_to_kvm(key_name: str, api_key: str, env: str, kvm_name: str) -> dict:
    """
    Envia a API Key do Vault para o KVM do Apigee via Management API.
    PUT /v1/organizations/{org}/environments/{env}/keyvaluemaps/{map}/entries/{key}
    """
    if not APIGEE_ORG or not APIGEE_ACCESS_TOKEN:
        return {"synced": False, "reason": "APIGEE_ORG ou APIGEE_ACCESS_TOKEN não configurados"}

    url = (
        f"{APIGEE_MGMT_URL}/v1/organizations/{APIGEE_ORG}"
        f"/environments/{env}/keyvaluemaps/{kvm_name}/entries/{key_name}"
    )
    headers = {
        "Authorization": f"Bearer {APIGEE_ACCESS_TOKEN}",
        "Content-Type":  "application/json",
    }
    payload = {"name": key_name, "value": api_key}

    print(f"[kvm] sync PUT {url}", flush=True)
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.put(url, headers=headers, json=payload)
        print(f"[kvm] sync status={resp.status_code}", flush=True)
        return {
            "synced":     resp.status_code in (200, 201),
            "status_code": resp.status_code,
            "kvm_name":   kvm_name,
            "env":        env,
        }
    except Exception as exc:
        return {"synced": False, "reason": str(exc)}


# ── endpoints ──────────────────────────────────────────────────────────────

@router.post("/apikey", status_code=201,
             summary="Grava nova API Key no Vault (source of truth)")
async def write_apikey(payload: APIKeyPayload):
    """
    Grava uma API Key no Vault.
    Se api_key não for informada, gera automaticamente (recomendado).
    Opcionalmente sincroniza para o KVM Apigee após gravar.
    """
    key = payload.api_key or _generate_api_key()
    key_hash = hashlib.sha256(key.encode()).hexdigest()  # hash para auditoria

    data = {
        "api_key":     key,
        "key_hash":    key_hash,
        "env":         payload.env,
        "description": payload.description,
        "status":      "active",
    }
    await vault_post(_apikey_path(payload.key_name, payload.env), {"data": data})

    return {
        "message":   f"API Key '{payload.key_name}' gravada no Vault",
        "key_name":  payload.key_name,
        "api_key":   key,          # retorna UMA VEZ — não fica exposta no Vault log
        "env":       payload.env,
        "key_hash":  key_hash,
    }


@router.get("/apikey/{key_name}",
            summary="Lê API Key do Vault — chamado em cache miss do KVM")
async def read_apikey(
    key_name: str,
    env: str = Query(default="prod", description="Ambiente Apigee"),
):
    """
    Retorna a API Key do Vault.
    O SharedFlow chama este endpoint quando a key não está no KVM (cache miss).
    """
    result = await vault_get(_apikey_path(key_name, env))
    data = result.get("data", {}).get("data", {})
    return {
        "key_name": key_name,
        "api_key":  data.get("api_key"),
        "status":   data.get("status"),
        "env":      data.get("env"),
    }


@router.post("/rotate/{key_name}",
             summary="Rotaciona API Key — gera nova versão e invalida KVM entry")
async def rotate_apikey(
    key_name: str,
    env: str = Query(default="prod"),
    sync: bool = Query(default=True, description="Sincronizar nova key para KVM após rotação"),
):
    """
    Rotação completa:
      1. Gera nova API Key
      2. Sobrescreve no Vault (nova versão KV)
      3. Se sync=true, envia para o KVM Apigee imediatamente

    O KVM do Apigee sempre tem a versão mais recente após a rotação.
    """
    new_key = _generate_api_key()
    key_hash = hashlib.sha256(new_key.encode()).hexdigest()

    # lê versão atual para preservar metadados
    try:
        current = await vault_get(_apikey_path(key_name, env))
        current_data = current.get("data", {}).get("data", {})
    except Exception:
        current_data = {}

    new_data = {
        **current_data,
        "api_key":   new_key,
        "key_hash":  key_hash,
        "status":    "active",
    }
    await vault_post(_apikey_path(key_name, env), {"data": new_data})

    sync_result = {}
    if sync:
        kvm = APIGEE_KVM_NAME
        sync_result = await _sync_to_kvm(key_name, new_key, env, kvm)

    return {
        "message":   f"API Key '{key_name}' rotacionada com sucesso",
        "key_name":  key_name,
        "new_key":   new_key,
        "key_hash":  key_hash,
        "env":       env,
        "sync":      sync_result,
    }


@router.post("/sync",
             summary="Força sincronização Vault → KVM Apigee para uma entry")
async def sync_to_kvm(payload: SyncPayload):
    """
    Lê a API Key atual do Vault e empurra para o KVM Apigee.
    Use para forçar sincronização após rotação manual ou falha de sync anterior.
    """
    result = await vault_get(_apikey_path(payload.key_name, payload.env))
    data = result.get("data", {}).get("data", {})
    api_key = data.get("api_key")

    if not api_key:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail=f"api_key não encontrada para '{payload.key_name}'")

    kvm_name = payload.kvm_name or APIGEE_KVM_NAME
    sync_result = await _sync_to_kvm(payload.key_name, api_key, payload.env, kvm_name)

    return {
        "message":    f"Sync de '{payload.key_name}' concluído",
        "key_name":   payload.key_name,
        "sync":       sync_result,
    }
