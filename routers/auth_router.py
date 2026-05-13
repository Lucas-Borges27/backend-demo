"""
routers/auth_router.py
──────────────────────────────────────────────────────────────────────────────
Mantém os endpoints originais /register e /login intactos.
Agora usa o vault_client centralizado em vez de chamar AppRole diretamente.
"""

import bcrypt
from fastapi import APIRouter
from fastapi import HTTPException
from pydantic import BaseModel

from core.vault_client import VAULT_ADDR, VAULT_NS, VAULT_MOUNT, vault_get, vault_post

router = APIRouter()


class UserPayload(BaseModel):
    user: str
    senha: str


def _user_path(user: str) -> str:
    return f"{VAULT_MOUNT}/data/usuarios/{user}"


@router.post("/register", status_code=201, summary="Cadastra usuário no Vault KV")
async def register(payload: UserPayload):
    path = _user_path(payload.user)

    # verifica se já existe
    try:
        await vault_get(path)
        raise HTTPException(status_code=409, detail="Usuário já existe")
    except HTTPException as exc:
        if exc.status_code != 404:
            raise  # re-lança 409 ou erros reais; 404 = ok, segue

    senha_hash = bcrypt.hashpw(payload.senha.encode(), bcrypt.gensalt()).decode()
    await vault_post(path, {"data": {"senha_hash": senha_hash}})

    return {"message": "Usuário cadastrado com sucesso", "user": payload.user}


@router.post("/login", summary="Valida credenciais do usuário no Vault KV")
async def login(payload: UserPayload):
    path = _user_path(payload.user)

    try:
        vault_data = await vault_get(path)
    except HTTPException as exc:
        if exc.status_code == 404:
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
        raise

    senha_hash = vault_data.get("data", {}).get("data", {}).get("senha_hash")
    if not senha_hash:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not bcrypt.checkpw(payload.senha.encode(), senha_hash.encode()):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    return {"message": "Login válido", "user": payload.user}
