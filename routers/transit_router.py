"""
routers/transit_router.py
──────────────────────────────────────────────────────────────────────────────
CASO DE USO 3 — JWT Signing via Transit Secrets Engine

A chave privada NUNCA sai do Vault. O Apigee envia o payload para assinar
e recebe o JWT completo (header.payload.signature).

Endpoints:
  POST /transit/setup-key          → cria a chave de assinatura no Transit
  POST /transit/sign               → assina JWT — chamado pelo SharedFlow
  POST /transit/verify             → verifica assinatura (opcional, para debug)

Variável de ambiente:
  VAULT_TRANSIT_MOUNT  → mount do Transit Engine (default: "transit")
  VAULT_JWT_KEY_NAME   → nome da chave de assinatura (default: "apigee-jwt")

Fluxo no Apigee:
  SharedFlow
    └─ JavaScript policy: monta header + payload base64url
    └─ Service Callout: POST /transit/sign  { header_b64, payload_b64, key_name }
    └─ JavaScript policy: monta JWT final = header.payload.{signature retornada}
    └─ AssignMessage: seta Authorization: Bearer {jwt}
"""

import os
import json
import base64
import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from core.vault_client import VAULT_TRANSIT_MOUNT, vault_get, vault_post

router = APIRouter()

VAULT_JWT_KEY_NAME = os.getenv("VAULT_JWT_KEY_NAME", "apigee-jwt")


# ── helpers base64url ──────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


# ── modelos ────────────────────────────────────────────────────────────────

class JWTSignRequest(BaseModel):
    claims: dict                           # claims do JWT (sub, iss, exp, etc.)
    key_name: Optional[str] = None         # sobrescreve VAULT_JWT_KEY_NAME
    hash_algorithm: Optional[str] = "sha2-256"
    ttl_seconds: Optional[int] = 3600      # exp automático se não estiver nos claims


class JWTVerifyRequest(BaseModel):
    jwt: str
    key_name: Optional[str] = None


class SetupKeyRequest(BaseModel):
    key_name: Optional[str] = None
    key_type: Optional[str] = "ecdsa-p256"   # ecdsa-p256 | rsa-4096 | ed25519


# ── endpoints ──────────────────────────────────────────────────────────────

@router.post("/setup-key", status_code=201,
             summary="Cria chave de assinatura JWT no Transit Engine")
async def setup_signing_key(req: SetupKeyRequest):
    """
    Cria (ou atualiza política de) uma chave no Transit Engine.
    Execute UMA VEZ durante o setup do ambiente.
    Chave ecdsa-p256 é recomendada para JWTs (ES256).
    """
    key_name = req.key_name or VAULT_JWT_KEY_NAME
    path = f"{VAULT_TRANSIT_MOUNT}/keys/{key_name}"

    await vault_post(path, {
        "type":                   req.key_type,
        "exportable":             False,   # chave NUNCA exportável
        "allow_plaintext_backup": False,
    })

    return {
        "message":   f"Chave '{key_name}' criada no Transit Engine",
        "key_name":  key_name,
        "key_type":  req.key_type,
        "exportable": False,
    }


@router.post("/sign",
             summary="Assina JWT — chave permanece no Vault (Transit Engine)")
async def sign_jwt(req: JWTSignRequest):
    """
    Assina um JWT usando o Transit Engine.
    A chave privada NUNCA é exposta — o Vault retorna apenas a assinatura.

    O SharedFlow monta os claims, chama este endpoint e recebe o JWT completo.

    Retorno:
      { "jwt": "header.payload.signature" }
    """
    key_name = req.key_name or VAULT_JWT_KEY_NAME

    # monta claims com exp automático se não informado
    claims = dict(req.claims)
    if "iat" not in claims:
        claims["iat"] = int(time.time())
    if "exp" not in claims and req.ttl_seconds:
        claims["exp"] = int(time.time()) + req.ttl_seconds

    # header JWT para ES256 (ecdsa-p256) ou RS256 conforme key_type
    alg_map = {
        "ecdsa-p256": "ES256",
        "ecdsa-p384": "ES384",
        "rsa-2048":   "RS256",
        "rsa-4096":   "RS256",
        "ed25519":    "EdDSA",
    }

    # descobre o tipo da chave
    try:
        key_info = await vault_get(f"{VAULT_TRANSIT_MOUNT}/keys/{key_name}")
        key_type = key_info.get("data", {}).get("type", "ecdsa-p256")
    except Exception:
        key_type = "ecdsa-p256"

    alg = alg_map.get(key_type, "ES256")
    header = {"alg": alg, "typ": "JWT"}

    header_b64  = b64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    payload_b64 = b64url_encode(json.dumps(claims,  separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    # Transit espera o input em base64 padrão (não urlsafe)
    input_b64 = base64.b64encode(signing_input.encode()).decode()

    sign_path = f"{VAULT_TRANSIT_MOUNT}/sign/{key_name}"
    sign_resp = await vault_post(sign_path, {
        "input":          input_b64,
        "hash_algorithm": req.hash_algorithm,
        "prehashed":      False,
    })

    # Vault retorna "vault:v1:<base64_signature>"
    raw_sig = sign_resp.get("data", {}).get("signature", "")
    if not raw_sig:
        raise HTTPException(status_code=502, detail="Transit Engine não retornou assinatura")

    # extrai apenas a parte base64 da assinatura
    sig_b64 = raw_sig.split(":")[-1]
    sig_b64url = b64url_encode(b64url_decode(sig_b64))

    jwt = f"{signing_input}.{sig_b64url}"

    return {
        "jwt":      jwt,
        "key_name": key_name,
        "alg":      alg,
        "claims":   claims,
    }


@router.post("/verify",
             summary="Verifica assinatura de JWT (Transit Engine) — uso em debug/teste")
async def verify_jwt(req: JWTVerifyRequest):
    """
    Verifica um JWT usando o Transit Engine.
    Útil para smoke tests e validação de setup.
    Em produção, o Apigee valida usando a chave pública exportada do Transit.
    """
    key_name = req.key_name or VAULT_JWT_KEY_NAME

    parts = req.jwt.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=400, detail="JWT malformado — esperado header.payload.signature")

    header_b64, payload_b64, sig_b64url = parts
    signing_input = f"{header_b64}.{payload_b64}"

    # re-encode assinatura para formato Vault
    sig_bytes  = b64url_decode(sig_b64url)
    sig_b64std = base64.b64encode(sig_bytes).decode()
    vault_sig  = f"vault:v1:{sig_b64std}"

    input_b64 = base64.b64encode(signing_input.encode()).decode()

    verify_path = f"{VAULT_TRANSIT_MOUNT}/verify/{key_name}"
    verify_resp = await vault_post(verify_path, {
        "input":     input_b64,
        "signature": vault_sig,
    })

    valid = verify_resp.get("data", {}).get("valid", False)

    # decodifica payload para exibir
    try:
        payload_json = json.loads(b64url_decode(payload_b64))
    except Exception:
        payload_json = {}

    return {
        "valid":    valid,
        "key_name": key_name,
        "claims":   payload_json,
    }


@router.get("/public-key/{key_name}",
            summary="Retorna chave pública para validação de JWTs no Apigee")
async def get_public_key(key_name: str):
    """
    Retorna a chave pública do Transit Engine.
    Use para configurar o TrustStore do Apigee ou o JWKS endpoint.
    """
    key_info = await vault_get(f"{VAULT_TRANSIT_MOUNT}/keys/{key_name}")
    keys_data = key_info.get("data", {}).get("keys", {})

    # pega a versão mais recente
    latest_version = str(key_info.get("data", {}).get("latest_version", 1))
    public_key_pem = keys_data.get(latest_version, {}).get("public_key", "")

    return {
        "key_name":      key_name,
        "latest_version": latest_version,
        "public_key_pem": public_key_pem,
    }
