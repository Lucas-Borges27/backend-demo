"""
routers/pki_router.py
──────────────────────────────────────────────────────────────────────────────
CASO DE USO 4 — mTLS entre Apigee e Backends (PKI Engine)

O Vault funciona como CA interno. Emite certificados cliente de curta duração
para que o Apigee X se autentique nos backends via mTLS.

Endpoints:
  POST /pki/issue                   → emite certificado cliente (chamado na renovação)
  GET  /pki/cert/{serial}           → lê certificado emitido pelo serial
  POST /pki/revoke                  → revoga certificado
  GET  /pki/ca/pem                  → retorna CA cert para configurar truststore backends
  GET  /pki/crl/pem                 → retorna CRL atual

Variáveis de ambiente:
  VAULT_PKI_MOUNT       → mount do PKI Engine (default: "pki")
  VAULT_PKI_ROLE        → role de emissão (default: "apigee-client")

Fluxo de renovação (executar via scheduler — ex: Cloud Scheduler GCP):
  1. POST /pki/issue → Vault emite cert + key
  2. Resultado gravado no Keystore do Apigee X (via Apigee Management API)
  3. Target Server passa a usar o novo cert nas chamadas mTLS
  4. Cert anterior expira no TTL configurado (ex: 7 dias)
"""

import os
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
import httpx

from core.vault_client import VAULT_PKI_MOUNT, vault_get, vault_post

router = APIRouter()

VAULT_PKI_ROLE = os.getenv("VAULT_PKI_ROLE", "apigee-client")

# config Apigee para importar o cert no Keystore
APIGEE_MGMT_URL     = os.getenv("APIGEE_MGMT_URL",     "https://apigee.googleapis.com")
APIGEE_ORG          = os.getenv("APIGEE_ORG",          "")
APIGEE_ENV          = os.getenv("APIGEE_ENV",           "prod")
APIGEE_ACCESS_TOKEN = os.getenv("APIGEE_ACCESS_TOKEN",  "")


# ── modelos ────────────────────────────────────────────────────────────────

class CertIssueRequest(BaseModel):
    common_name: Optional[str] = "apigee-proxy.interno"
    ttl: Optional[str] = "168h"           # 7 dias — renovação semanal
    role: Optional[str] = None            # sobrescreve VAULT_PKI_ROLE
    alt_names: Optional[str] = None       # SANs adicionais separados por vírgula
    ip_sans: Optional[str] = None
    import_to_apigee: Optional[bool] = False
    apigee_keystore: Optional[str] = "vault-mtls-keystore"
    apigee_alias: Optional[str] = "vault-client-cert"


class CertRevokeRequest(BaseModel):
    serial_number: str


# ── helpers ────────────────────────────────────────────────────────────────

async def _import_cert_to_apigee(
    cert_pem: str,
    key_pem: str,
    env: str,
    keystore_name: str,
    alias: str,
) -> dict:
    """
    Importa certificado + chave privada no Keystore do Apigee X.
    POST /v1/organizations/{org}/environments/{env}/keystores/{ks}/aliases?format=keycertpair
    """
    if not APIGEE_ORG or not APIGEE_ACCESS_TOKEN:
        return {"imported": False, "reason": "APIGEE_ORG ou APIGEE_ACCESS_TOKEN não configurados"}

    # garante que o keystore existe
    ks_url = f"{APIGEE_MGMT_URL}/v1/organizations/{APIGEE_ORG}/environments/{env}/keystores"
    alias_url = (
        f"{APIGEE_MGMT_URL}/v1/organizations/{APIGEE_ORG}"
        f"/environments/{env}/keystores/{keystore_name}/aliases"
        f"?format=keycertpair&alias={alias}&ignoreExpiryValidation=true"
    )
    headers = {
        "Authorization": f"Bearer {APIGEE_ACCESS_TOKEN}",
        "Content-Type":  "application/json",
    }

    print(f"[pki] import cert → {alias_url}", flush=True)
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            # cria keystore se não existir
            await client.post(ks_url, headers=headers, json={"name": keystore_name})

            # importa cert + key
            resp = await client.post(alias_url, headers=headers, json={
                "certFile": cert_pem,
                "keyFile":  key_pem,
            })

        print(f"[pki] import status={resp.status_code}", flush=True)
        return {
            "imported":    resp.status_code in (200, 201),
            "status_code": resp.status_code,
            "keystore":    keystore_name,
            "alias":       alias,
            "env":         env,
        }
    except Exception as exc:
        return {"imported": False, "reason": str(exc)}


# ── endpoints ──────────────────────────────────────────────────────────────

@router.post("/issue", status_code=201,
             summary="Emite certificado cliente mTLS — Vault como CA interno")
async def issue_certificate(req: CertIssueRequest):
    """
    Emite um certificado X.509 cliente de curta duração.
    Usado pelo Apigee X para autenticação mútua nos backends.

    Se import_to_apigee=true, importa automaticamente no Keystore do Apigee.
    Recomendado chamar via Cloud Scheduler (renovação periódica).

    Retorno inclui:
      - certificate: cert PEM (público)
      - private_key: chave privada PEM (NUNCA logar em produção)
      - serial_number: para revogação
      - expiration: unix timestamp
    """
    role = req.role or VAULT_PKI_ROLE
    issue_path = f"{VAULT_PKI_MOUNT}/issue/{role}"

    issue_payload = {
        "common_name": req.common_name,
        "ttl":         req.ttl,
    }
    if req.alt_names:
        issue_payload["alt_names"] = req.alt_names
    if req.ip_sans:
        issue_payload["ip_sans"] = req.ip_sans

    result = await vault_post(issue_path, issue_payload)
    data   = result.get("data", {})

    cert_pem    = data.get("certificate", "")
    key_pem     = data.get("private_key", "")
    serial      = data.get("serial_number", "")
    ca_chain    = data.get("ca_chain", [])
    expiration  = data.get("expiration", 0)

    response = {
        "message":       "Certificado emitido com sucesso",
        "serial_number": serial,
        "common_name":   req.common_name,
        "ttl":           req.ttl,
        "expiration":    expiration,
        "certificate":   cert_pem,
        "private_key":   key_pem,   # atenção: exposto apenas neste momento
        "ca_chain":      ca_chain,
    }

    if req.import_to_apigee:
        import_result = await _import_cert_to_apigee(
            cert_pem=cert_pem,
            key_pem=key_pem,
            env=APIGEE_ENV,
            keystore_name=req.apigee_keystore,
            alias=req.apigee_alias,
        )
        response["apigee_import"] = import_result

    return response


@router.get("/cert/{serial}",
            summary="Lê certificado emitido pelo número serial")
async def get_certificate(serial: str):
    """
    Retorna os dados de um certificado pelo número serial.
    Útil para auditoria e verificação de validade.
    """
    result = await vault_get(f"{VAULT_PKI_MOUNT}/cert/{serial}")
    data   = result.get("data", {})
    return {
        "serial_number": serial,
        "certificate":   data.get("certificate"),
        "revocation_time": data.get("revocation_time", 0),
    }


@router.post("/revoke",
             summary="Revoga certificado pelo número serial")
async def revoke_certificate(req: CertRevokeRequest):
    """
    Revoga um certificado imediatamente.
    O serial aparece na CRL — os backends devem verificar a CRL ou usar OCSP.
    """
    result = await vault_post(f"{VAULT_PKI_MOUNT}/revoke", {
        "serial_number": req.serial_number,
    })
    data = result.get("data", {})
    return {
        "message":         f"Certificado {req.serial_number} revogado",
        "revocation_time": data.get("revocation_time"),
    }


@router.get("/ca/pem",
            summary="Retorna CA certificate PEM — configure nos backends como truststore")
async def get_ca_pem():
    """
    Retorna o certificado da CA em formato PEM.
    Os backends devem confiar nesta CA para validar o cert do Apigee no mTLS.

    Use este endpoint para:
      1. Configurar o truststore dos backends
      2. Atualizar automaticamente quando a CA for renovada
    """
    result = await vault_get(f"{VAULT_PKI_MOUNT}/ca/pem")
    # /ca/pem retorna texto puro — o vault_get retornará um dict com o conteúdo
    ca_pem = result if isinstance(result, str) else result.get("data", "")
    return {
        "ca_pem":  ca_pem,
        "pki_mount": VAULT_PKI_MOUNT,
    }


@router.get("/crl/pem",
            summary="Retorna CRL atual — configure nos backends para validação de revogação")
async def get_crl_pem():
    """
    Retorna a Certificate Revocation List (CRL) em formato PEM.
    Configure nos backends para rejeitar certificados revogados.
    """
    result = await vault_get(f"{VAULT_PKI_MOUNT}/crl/pem")
    crl_pem = result if isinstance(result, str) else result.get("data", "")
    return {
        "crl_pem":   crl_pem,
        "pki_mount": VAULT_PKI_MOUNT,
    }
