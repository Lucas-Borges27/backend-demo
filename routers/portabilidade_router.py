"""
routers/portabilidade_router.py
──────────────────────────────────────────────────────────────────────────────
CENÁRIO b — mTLS entre Apigee e Backend (PKI Engine)

O Vault funciona como CA interno. O Apigee X apresenta um certificado cliente
emitido pelo Vault PKI — o backend valida o cert antes de responder.

Sem certificado válido assinado pelo CA do Vault → 401.
Com certificado válido → dados de portabilidade retornados.

Endpoint:
  GET /portabilidade/{cpf}

Como o Cloud Run funciona:
  O Cloud Run gerenciado não faz mTLS nativo — o TLS é terminado antes de
  chegar na aplicação. O Apigee envia o certificado cliente no header
  "x-client-cert" (PEM base64). O backend valida a assinatura contra o CA
  do Vault.

  O CA cert é lido de /vault/secrets/ca.crt — renderizado pelo Vault Agent.
  Fallback para env var MTLS_CA_CERT_PEM em dev local.

Variáveis de ambiente:
  MTLS_CA_CERT_PEM   → CA cert PEM completo (fallback dev local)
  MTLS_CN_REQUIRED   → CN esperado no cert cliente
                       (default: apigee.telecom-demo.internal)
"""

import base64
import os
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509 import NameOID
from fastapi import APIRouter, Header, HTTPException
from typing import Annotated

router = APIRouter()

VAULT_CA_CERT_PATH = "/vault/secrets/ca.crt"
MTLS_CN_REQUIRED   = os.getenv("MTLS_CN_REQUIRED", "apigee.telecom-demo.internal")


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


# ── helpers ────────────────────────────────────────────────────────────────

def _load_ca_cert() -> x509.Certificate:
    """
    Carrega o CA cert do Vault Agent (/vault/secrets/ca.crt).
    Fallback para env var MTLS_CA_CERT_PEM em dev local.
    """
    pem = ""

    try:
        with open(VAULT_CA_CERT_PATH, "r") as f:
            pem = f.read().strip()
    except FileNotFoundError:
        pass

    if not pem:
        pem = os.getenv("MTLS_CA_CERT_PEM", "").strip()

    if not pem:
        raise HTTPException(
            status_code=503,
            detail="CA cert não disponível — Vault Agent não inicializado",
        )

    return x509.load_pem_x509_certificate(pem.encode())


def _validate_client_cert(cert_pem: str) -> dict:
    """
    Valida o certificado cliente contra o CA do Vault.
    Verifica: assinatura, validade temporal e CN esperado.
    Retorna os dados do cert para incluir no response.
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

    # 3. Assinatura — verifica que foi emitido pelo CA do Vault
    ca_cert = _load_ca_cert()
    try:
        ca_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            client_cert.signature_hash_algorithm,
        )
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Assinatura do certificado cliente inválida — não emitido pelo CA Vault",
        )

    return {
        "subject":     client_cert.subject.rfc4514_string(),
        "issuer":      client_cert.issuer.rfc4514_string(),
        "serial":      hex(client_cert.serial_number),
        "valid_from":  client_cert.not_valid_before_utc.isoformat(),
        "valid_until": client_cert.not_valid_after_utc.isoformat(),
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
    O certificado deve ter sido emitido pelo Vault PKI (CA interno VaultFone).

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

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        **portabilidade,
        "_meta": {
            "auth_method":           "mTLS — Vault PKI como CA interno",
            "ca_source":             VAULT_CA_CERT_PATH,
            "client_cert":           cert_info,
            "hardcoded_credentials": False,
        },
    }