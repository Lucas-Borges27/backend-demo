"""
routers/portabilidade_router.py
──────────────────────────────────────────────────────────────────────────────
CENÁRIO b — mTLS entre Apigee e Backend (PKI Engine)

O CA cert é obtido diretamente do endpoint público do Vault PKI e mantido em
cache em memória com TTL (MTLS_CA_TTL_SECONDS, default 3600). Se uma validação
falhar, o cache é invalidado e o CA é renovado antes de retornar 401 — garante
funcionamento imediato após rotação do CA no Vault.

Endpoint público (sem token):
  GET /v1/pki/issuer/e9f0a792-2407-a20c-3399-c53b64ac1249/pem
  Header: X-Vault-Namespace: admin/ibm

Variáveis de ambiente:
  MTLS_CN_REQUIRED      → CN esperado no cert cliente
                          (default: apigee.telecom-demo.internal)
  MTLS_CA_TTL_SECONDS   → TTL do cache do CA cert em segundos (default: 3600)
"""

import base64
import os
import time
from datetime import datetime, timezone
from threading import Lock

import httpx
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509 import NameOID
from fastapi import APIRouter, Header, HTTPException
from typing import Annotated

router = APIRouter()

VAULT_BASE_URL   = "https://do-not-delete-ever-v2-public-vault-cf6a1d76.5773df81.z1.hashicorp.cloud:8200"
VAULT_NAMESPACE  = "admin/ibm"
VAULT_PKI_ISSUER = "e9f0a792-2407-a20c-3399-c53b64ac1249"
MTLS_CN_REQUIRED = os.getenv("MTLS_CN_REQUIRED", "apigee.telecom-demo.internal")
MTLS_CA_TTL      = int(os.getenv("MTLS_CA_TTL_SECONDS", "3600"))


# ── cache em memória ───────────────────────────────────────────────────────

_ca_cache: dict = {"cert": None, "fetched_at": 0.0}
_ca_lock  = Lock()


def _fetch_ca_from_vault() -> x509.Certificate:
    url = f"{VAULT_BASE_URL}/v1/pki/issuer/{VAULT_PKI_ISSUER}/pem"
    try:
        resp = httpx.get(
            url,
            headers={"X-Vault-Namespace": VAULT_NAMESPACE},
            timeout=5.0,
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(status_code=503, detail=f"Falha ao obter CA cert do Vault PKI: {e}")

    pem = resp.text.strip()
    if not pem:
        raise HTTPException(status_code=503, detail="Vault PKI retornou CA cert vazio")

    return x509.load_pem_x509_certificate(pem.encode())


def _load_ca_cert() -> x509.Certificate:
    """
    Retorna o CA cert do cache em memória.
    Renova via Vault PKI se o TTL expirou.
    Thread-safe via Lock.
    """
    now = time.monotonic()
    with _ca_lock:
        if _ca_cache["cert"] is None or (now - _ca_cache["fetched_at"]) > MTLS_CA_TTL:
            _ca_cache["cert"]       = _fetch_ca_from_vault()
            _ca_cache["fetched_at"] = now
    return _ca_cache["cert"]


def _invalidate_ca_cache() -> None:
    """Força renovação do CA no próximo _load_ca_cert()."""
    with _ca_lock:
        _ca_cache["fetched_at"] = 0.0


# ── helpers ────────────────────────────────────────────────────────────────

def _verify_signature(client_cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    try:
        ca_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        return False


def _validate_client_cert(cert_pem: str) -> dict:
    """
    Valida o certificado cliente contra o CA obtido do Vault PKI.
    Verifica: assinatura, validade temporal e CN esperado.
    Se a validação de assinatura falhar, invalida o cache e retenta uma vez
    para cobrir rotação do CA no Vault.
    """
    try:
        cert_bytes = (
            base64.b64decode(cert_pem)
            if not cert_pem.startswith("-----")
            else cert_pem.encode()
        )
        client_cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        raise HTTPException(status_code=401, detail="Certificado cliente inválido ou malformado")

    # 1. Validade temporal
    now = datetime.now(timezone.utc)
    if now < client_cert.not_valid_before_utc:
        raise HTTPException(status_code=401, detail="Certificado cliente ainda não é válido")
    if now > client_cert.not_valid_after_utc:
        raise HTTPException(status_code=401, detail="Certificado cliente expirado")

    # 2. CN esperado
    cn_values = [
        attr.value
        for attr in client_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ]
    if MTLS_CN_REQUIRED not in cn_values:
        raise HTTPException(
            status_code=401,
            detail=f"CN inválido — esperado '{MTLS_CN_REQUIRED}', recebido '{cn_values}'",
        )

    # 3. Assinatura — tenta com CA em cache, renova e retenta se falhar
    if not _verify_signature(client_cert, _load_ca_cert()):
        _invalidate_ca_cache()
        if not _verify_signature(client_cert, _load_ca_cert()):
            raise HTTPException(
                status_code=401,
                detail="Assinatura do certificado cliente inválida — não emitido pelo CA apigee-ca",
            )

    return {
        "subject":     client_cert.subject.rfc4514_string(),
        "issuer":      client_cert.issuer.rfc4514_string(),
        "serial":      hex(client_cert.serial_number),
        "valid_from":  client_cert.not_valid_before_utc.isoformat(),
        "valid_until": client_cert.not_valid_after_utc.isoformat(),
    }


# ── dados de portabilidade (seed para demo) ────────────────────────────────

_PORTABILIDADE = {
    "111.111.111-11": {
        "nome": "João Silva",
        "numero": "+55 11 91234-5678",
        "operadora_origem": "OperadoraX",
        "operadora_destino": "VaultFone",
        "status": "em_andamento",
        "protocolo": "PORT-2025-00123",
        "data_solicitacao": "2025-05-10T09:00:00Z",
        "previsao_conclusao": "2025-05-17T18:00:00Z",
        "etapas": [
            {"etapa": "Solicitação recebida",         "status": "concluida",  "data": "2025-05-10T09:00:00Z"},
            {"etapa": "Validação cadastral",          "status": "concluida",  "data": "2025-05-10T11:30:00Z"},
            {"etapa": "Confirmação operadora origem", "status": "pendente",   "data": None},
            {"etapa": "Ativação VaultFone",           "status": "pendente",   "data": None},
        ],
    },
    "222.222.222-22": {
        "nome": "Maria Santos",
        "numero": "+55 21 98765-4321",
        "operadora_origem": "OperadoraY",
        "operadora_destino": "VaultFone",
        "status": "concluida",
        "protocolo": "PORT-2025-00089",
        "data_solicitacao": "2025-04-28T14:00:00Z",
        "previsao_conclusao": "2025-05-05T18:00:00Z",
        "etapas": [
            {"etapa": "Solicitação recebida",         "status": "concluida", "data": "2025-04-28T14:00:00Z"},
            {"etapa": "Validação cadastral",          "status": "concluida", "data": "2025-04-28T16:00:00Z"},
            {"etapa": "Confirmação operadora origem", "status": "concluida", "data": "2025-04-30T10:00:00Z"},
            {"etapa": "Ativação VaultFone",           "status": "concluida", "data": "2025-05-05T17:45:00Z"},
        ],
    },
}


# ── endpoint ───────────────────────────────────────────────────────────────

@router.get(
    "/{cpf}",
    summary="Portabilidade numérica — protegida por mTLS (Vault PKI como CA interno)",
)
async def get_portabilidade(
    cpf: str,
    x_client_cert: Annotated[str | None, Header(alias="x-client-cert")] = None,
):
    """
    Retorna o status de portabilidade do CPF informado.

    Requer certificado cliente válido no header **x-client-cert** (PEM base64).
    O certificado deve ter sido emitido pelo Vault PKI — issuer apigee-ca.

    Sem certificado → 401
    Certificado inválido ou de outra CA → 401
    Certificado válido → 200 com dados de portabilidade
    """
    if not x_client_cert:
        raise HTTPException(
            status_code=401,
            detail="Certificado cliente ausente — autenticação mTLS obrigatória para portabilidade",
            headers={"WWW-Authenticate": "Certificate"},
        )

    cert_info = _validate_client_cert(x_client_cert)

    portabilidade = _PORTABILIDADE.get(cpf)
    if portabilidade is None:
        raise HTTPException(
            status_code=404,
            detail=f"Nenhuma portabilidade encontrada para CPF {cpf}",
        )

    ca_age_seconds = int(time.monotonic() - _ca_cache["fetched_at"])

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        **portabilidade,
        "_meta": {
            "auth_method":           "mTLS — Vault PKI como CA interno",
            "ca_source":             f"{VAULT_BASE_URL}/v1/pki/issuer/{VAULT_PKI_ISSUER}/pem",
            "ca_issuer_id":          VAULT_PKI_ISSUER,
            "ca_cache_age_seconds":  ca_age_seconds,
            "ca_ttl_seconds":        MTLS_CA_TTL,
            "client_cert":           cert_info,
            "hardcoded_credentials": False,
        },
    }