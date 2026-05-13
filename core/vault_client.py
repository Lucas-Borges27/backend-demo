"""
core/vault_client.py
──────────────────────────────────────────────────────────────────────────────
Configuração mínima para o backend atuar como Resource Server passivo.

Responsabilidades:
  • Carregar a chave pública usada para verificar JWTs emitidos via Vault Transit
  • Validar assinatura e claims básicas do JWT localmente
  • Expor somente configuração necessária ao runtime FastAPI

Não há mais login AppRole, chamadas ao Vault KV ou uso de Transit a partir deste backend.
Toda a emissão e gestão do token fica no Apigee X.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any


JWT_PUBLIC_KEY_PEM = os.getenv("JWT_PUBLIC_KEY_PEM", "")
JWT_ISSUER = os.getenv("JWT_ISSUER", "apigee-vault-demo")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "faturas-backend")
JWT_SUBJECT_CLAIM = os.getenv("JWT_SUBJECT_CLAIM", "sub")
JWT_NAME_CLAIM = os.getenv("JWT_NAME_CLAIM", "nome")
JWT_LEEWAY_SECONDS = int(os.getenv("JWT_LEEWAY_SECONDS", "30"))


def get_resource_server_config() -> dict[str, Any]:
    """Retorna a configuração necessária para validar JWT no backend."""
    return {
        "public_key_pem": JWT_PUBLIC_KEY_PEM.strip(),
        "issuer": JWT_ISSUER,
        "audience": JWT_AUDIENCE,
        "subject_claim": JWT_SUBJECT_CLAIM,
        "name_claim": JWT_NAME_CLAIM,
        "leeway_seconds": JWT_LEEWAY_SECONDS,
    }


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _load_public_key(public_key_pem: str):
    if not public_key_pem:
        raise ValueError("Chave pública JWT não configurada")
    try:
        from cryptography.hazmat.primitives import serialization

        return serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Chave pública JWT inválida: {exc}") from exc


def _verify_signature(signing_input: bytes, signature: bytes, public_key) -> None:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    except Exception as exc:
        raise ValueError(f"Dependência criptográfica indisponível: {exc}") from exc

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return

    if isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, signing_input, ec.ECDSA(hashes.SHA256()))
        return

    raise ValueError("Tipo de chave pública não suportado para validação JWT")


def verify_jwt(token: str, config: dict[str, Any]) -> dict[str, Any]:
    """
    Valida localmente um JWT assinado pelo Vault Transit.
    Aceita somente JWS compacto com algoritmo RS256 ou ES256.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise ValueError("Token inválido") from exc

    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except Exception as exc:
        raise ValueError(f"Token malformado: {exc}") from exc

    alg = header.get("alg")
    if alg not in {"RS256", "ES256"}:
        raise ValueError("Algoritmo JWT não suportado")

    public_key = _load_public_key(config["public_key_pem"])
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

    try:
        _verify_signature(signing_input, signature, public_key)
    except Exception as exc:
        raise ValueError(f"Assinatura JWT inválida: {exc}") from exc

    now = int(time.time())
    leeway = int(config.get("leeway_seconds", 0))

    issuer = config.get("issuer")
    if issuer and payload.get("iss") != issuer:
        raise ValueError("Issuer inválido")

    audience = config.get("audience")
    aud_claim = payload.get("aud")
    if audience:
        if isinstance(aud_claim, list):
            if audience not in aud_claim:
                raise ValueError("Audience inválida")
        elif aud_claim != audience:
            raise ValueError("Audience inválida")

    exp = payload.get("exp")
    if exp is not None and now > int(exp) + leeway:
        raise ValueError("Token expirado")

    nbf = payload.get("nbf")
    if nbf is not None and now + leeway < int(nbf):
        raise ValueError("Token ainda não é válido")

    iat = payload.get("iat")
    if iat is not None and now + leeway < int(iat):
        raise ValueError("Token com iat no futuro")

    subject_claim = config.get("subject_claim", "sub")
    subject_value = payload.get(subject_claim)
    if not isinstance(subject_value, str) or not subject_value.strip():
        raise ValueError(f"Claim obrigatória ausente: {subject_claim}")

    return payload
