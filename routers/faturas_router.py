"""
routers/faturas_router.py
──────────────────────────────────────────────────────────────────────────────
Resource server passivo para o caso de uso VaultFone.

Responsabilidades:
  • Receber JWT já emitido pelo Apigee X
  • Consumir claims previamente validados pelo middleware global
  • Entregar apenas os recursos protegidos

Endpoints:
  GET /faturas/{cpf}              → lista faturas do titular autenticado
  GET /faturas/{cpf}/{fatura_id}  → detalha uma fatura do titular autenticado
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


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
                {"descricao": "Plano Ouro 30GB",                "valor": 99.90},
                {"descricao": "Roaming internacional (3 dias)", "valor": 20.00},
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
                {"descricao": "Multa por atraso (2%)", "valor": 2.00},
            ],
        },
    ],
}


def _get_claims(request: Request) -> dict[str, Any]:
    claims = getattr(request.state, "jwt_claims", None)
    if not isinstance(claims, dict):
        raise HTTPException(status_code=401, detail="Claims JWT ausentes na requisição")
    return claims


def _get_authenticated_cpf(request: Request) -> str:
    claims = _get_claims(request)
    config = request.app.state.resource_server_config
    subject_claim = config.get("subject_claim", "sub")
    cpf = claims.get(subject_claim)

    if not isinstance(cpf, str) or not cpf.strip():
        raise HTTPException(status_code=401, detail="CPF ausente no token")
    return cpf


def _get_authenticated_name(request: Request) -> str:
    claims = _get_claims(request)
    config = request.app.state.resource_server_config
    name_claim = config.get("name_claim", "nome")
    nome = claims.get(name_claim, "")
    return nome if isinstance(nome, str) else ""


@router.get("/{cpf}", summary="Lista faturas VaultFone do CPF autenticado")
async def list_faturas(cpf: str, request: Request):
    authenticated_cpf = _get_authenticated_cpf(request)
    if authenticated_cpf != cpf:
        raise HTTPException(status_code=403, detail="Token não pertence a este CPF")

    faturas = _FATURAS.get(cpf)
    if faturas is None:
        raise HTTPException(status_code=404, detail=f"Nenhuma fatura encontrada para CPF {cpf}")

    resumo = [{k: v for k, v in f.items() if k != "itens"} for f in faturas]

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        "nome": _get_authenticated_name(request),
        "faturas": resumo,
    }


@router.get("/{cpf}/{fatura_id}", summary="Detalhe de fatura VaultFone do CPF autenticado")
async def get_fatura(cpf: str, fatura_id: str, request: Request):
    authenticated_cpf = _get_authenticated_cpf(request)
    if authenticated_cpf != cpf:
        raise HTTPException(status_code=403, detail="Token não pertence a este CPF")

    faturas = _FATURAS.get(cpf)
    if faturas is None:
        raise HTTPException(status_code=404, detail=f"Nenhuma fatura encontrada para CPF {cpf}")

    fatura = next((f for f in faturas if f["id"] == fatura_id), None)
    if fatura is None:
        raise HTTPException(status_code=404, detail=f"Fatura {fatura_id} não encontrada")

    return {
        "operadora": "VaultFone",
        "cpf": cpf,
        "nome": _get_authenticated_name(request),
        "fatura": fatura,
    }
