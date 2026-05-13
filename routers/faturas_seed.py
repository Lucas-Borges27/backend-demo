"""
routers/faturas_seed.py
──────────────────────────────────────────────────────────────────────────────
Seed lógico de usuários de demo para o cenário Faturas VaultFone.

Neste novo desenho o backend não grava mais segredos no Vault.
A preparação de credenciais/JWT é responsabilidade da infraestrutura e do Apigee.

Endpoint:
  POST /faturas/seed → apenas simula a disponibilidade dos usuários de demo
"""

import bcrypt
from fastapi import APIRouter

router = APIRouter()

_DEMO_USERS = [
    {"cpf": "111.111.111-11", "nome": "João Silva", "senha": "demo123"},
    {"cpf": "222.222.222-22", "nome": "Maria Santos", "senha": "demo123"},
]


@router.post("/seed", status_code=200, summary="Simula a preparação dos usuários de demo")
async def seed_usuarios():
    """
    Não persiste dados no Vault nem em banco local.
    Apenas retorna a lista de usuários demo esperados pelo cenário,
    incluindo hash bcrypt gerado em memória para fins de conferência.
    """
    prepared = []
    for user in _DEMO_USERS:
        senha_hash = bcrypt.hashpw(user["senha"].encode(), bcrypt.gensalt()).decode()
        prepared.append(
            {
                "cpf": user["cpf"],
                "nome": user["nome"],
                "senha_hash_preview": senha_hash[:20],
                "provisioning": "externalized",
            }
        )

    return {
        "message": "Seed lógico concluído. Nenhuma escrita em Vault foi executada.",
        "usuarios": prepared,
    }
