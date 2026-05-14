"""
routers/extrato_router.py
Cenário d — Credenciais de Target Server via Vault KV

Endpoint:
  GET /extrato/{cpf}   → retorna extrato de consumo do CPF
                         exige Header: x-api-key: <valor>
"""

import os
from fastapi import APIRouter, Header, HTTPException
from typing import Annotated

router = APIRouter()

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


@router.get("/{cpf}", summary="Extrato de consumo — protegido por x-api-key via Vault KV")
async def get_extrato(
    cpf: str,
    x_api_key: Annotated[str | None, Header(alias="x-api-key")] = None,
):
    expected_key = os.getenv("EXTRATO_API_KEY", "")
    if not expected_key:
        raise HTTPException(status_code=503, detail="EXTRATO_API_KEY não configurada no servidor")

    if not x_api_key or x_api_key != expected_key:
        raise HTTPException(
            status_code=401,
            detail="x-api-key ausente ou inválida",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    extrato = _EXTRATO.get(cpf)
    if extrato is None:
        raise HTTPException(status_code=404, detail=f"Nenhum extrato encontrado para CPF {cpf}")

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        **extrato,
        "_meta": {
            "auth_method": "x-api-key via Vault KV",
            "key_source": "Vault KV: kvapigee-demo/extrato-api-key",
            "hardcoded_in_apigee": False,
        },
    }