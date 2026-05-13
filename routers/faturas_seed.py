"""
routers/faturas_seed.py
──────────────────────────────────────────────────────────────────────────────
Seed de usuários de demo para o cenário Faturas VaultFone.
Execute UMA VEZ antes de testar o fluxo completo.

Endpoint:
  POST /faturas/seed  → cria 2 usuários no Vault KV (kvapigee-demo)

Variável de ambiente:
  VAULT_KV_DEMO  → mount do KV de demo (default: "kvapigee-demo")
"""

import os
import bcrypt
from fastapi import APIRouter

from core.vault_client import vault_post

router = APIRouter()

VAULT_KV_DEMO = os.getenv("VAULT_KV_DEMO", "kvapigee-demo")

_DEMO_USERS = [
    {"cpf": "111.111.111-11", "nome": "João Silva",   "senha": "demo123"},
    {"cpf": "222.222.222-22", "nome": "Maria Santos", "senha": "demo123"},
]


@router.post("/seed", status_code=201,
             summary="Cria usuários de demo no Vault KV (kvapigee-demo)")
async def seed_usuarios():
    """
    Cria (ou sobrescreve) os 2 usuários de demo no Vault KV.
    Senha armazenada como bcrypt hash — nunca em plaintext.
    """
    created = []
    for u in _DEMO_USERS:
        senha_hash = bcrypt.hashpw(u["senha"].encode(), bcrypt.gensalt()).decode()
        path = f"{VAULT_KV_DEMO}/data/usuarios/{u['cpf']}"
        await vault_post(path, {
            "data": {
                "senha_hash": senha_hash,
                "nome":       u["nome"],
                "cpf":        u["cpf"],
            }
        })
        created.append({"cpf": u["cpf"], "nome": u["nome"]})

    return {
        "message":  f"{len(created)} usuários de demo criados em '{VAULT_KV_DEMO}'",
        "usuarios": created,
    }
