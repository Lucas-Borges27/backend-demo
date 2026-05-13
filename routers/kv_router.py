"""
routers/kv_router.py
──────────────────────────────────────────────────────────────────────────────
CASO DE USO 1 — Credenciais de Backends e Consumidores (KV Secrets Engine)

Endpoints:
  POST /kv/backend                → grava credencial de um backend (target server)
  GET  /kv/backend/{target}       → lê credencial de um backend (chamado pelo SharedFlow)
  POST /kv/consumer               → grava credencial de um consumidor da API
  GET  /kv/consumer/{consumer}    → lê credencial de um consumidor
  POST /kv/sharedflow/{context}   → grava credencial no contexto do SharedFlow
  GET  /kv/sharedflow/{context}   → lê credencial no contexto do SharedFlow

Estrutura dos segredos no Vault:
  secret/data/apigee/backends/{target}     → creds do backend
  secret/data/apigee/consumers/{consumer}  → creds do consumidor
  secret/data/apigee/sharedflow/{context}  → creds no contexto do SharedFlow

Como o SharedFlow usa esses endpoints:
  1. Service Callout policy → GET /kv/backend/{target}
  2. Extrai usuario/senha/token da resposta JSON
  3. Injeta no header da requisição de saída (AssignMessage policy)
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from core.vault_client import VAULT_MOUNT, vault_get, vault_post

router = APIRouter()


# ── modelos ────────────────────────────────────────────────────────────────

class BackendCredential(BaseModel):
    target: str                      # nome do target server ex: "meu-sistema-erp"
    auth_type: str                   # "basic" | "bearer" | "apikey"
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    api_key: Optional[str] = None
    header_name: Optional[str] = None  # ex: "X-API-Key" para auth_type=apikey


class ConsumerCredential(BaseModel):
    consumer: str                    # identificador do consumidor ex: "app-parceiro-xyz"
    api_key: str
    scopes: Optional[list[str]] = []
    description: Optional[str] = None


class SharedFlowCredential(BaseModel):
    context: str                     # nome do contexto/SharedFlow
    data: dict                       # dados livres a serem armazenados


# ── helpers de path ────────────────────────────────────────────────────────

def _backend_path(target: str) -> str:
    return f"{VAULT_MOUNT}/data/apigee/backends/{target}"

def _consumer_path(consumer: str) -> str:
    return f"{VAULT_MOUNT}/data/apigee/consumers/{consumer}"

def _sharedflow_path(context: str) -> str:
    return f"{VAULT_MOUNT}/data/apigee/sharedflow/{context}"


# ── backends ───────────────────────────────────────────────────────────────

@router.post("/backend", status_code=201,
             summary="Grava credencial de um backend (Target Server)")
async def write_backend(cred: BackendCredential):
    """
    Grava as credenciais de um backend no Vault.
    Chamado durante o onboarding de um novo Target Server no Apigee.
    """
    payload_data = {
        "auth_type":   cred.auth_type,
        "username":    cred.username,
        "password":    cred.password,
        "token":       cred.token,
        "api_key":     cred.api_key,
        "header_name": cred.header_name,
    }
    # remove campos None para não poluir o segredo
    payload_data = {k: v for k, v in payload_data.items() if v is not None}

    await vault_post(_backend_path(cred.target), {"data": payload_data})
    return {
        "message": f"Credencial do backend '{cred.target}' gravada com sucesso",
        "path":    _backend_path(cred.target),
    }


@router.get("/backend/{target}",
            summary="Lê credencial de um backend — chamado pelo SharedFlow Apigee")
async def read_backend(target: str):
    """
    Retorna as credenciais do backend para o SharedFlow injetar
    no header da requisição de saída (AssignMessage policy).

    Resposta usada pelo SharedFlow:
      - auth_type: "basic"  → monta Authorization: Basic base64(username:password)
      - auth_type: "bearer" → monta Authorization: Bearer {token}
      - auth_type: "apikey" → monta {header_name}: {api_key}
    """
    result = await vault_get(_backend_path(target))
    data = result.get("data", {}).get("data", {})
    return {
        "target":    target,
        "auth_type": data.get("auth_type"),
        "username":  data.get("username"),
        "password":  data.get("password"),
        "token":     data.get("token"),
        "api_key":   data.get("api_key"),
        "header_name": data.get("header_name"),
    }


# ── consumidores ───────────────────────────────────────────────────────────

@router.post("/consumer", status_code=201,
             summary="Grava credencial de um consumidor da API")
async def write_consumer(cred: ConsumerCredential):
    """
    Grava a API Key e metadados de um consumidor.
    Usado para onboarding de apps/parceiros que consomem as APIs Apigee.
    """
    payload_data = {
        "api_key":     cred.api_key,
        "scopes":      cred.scopes,
        "description": cred.description,
    }
    await vault_post(_consumer_path(cred.consumer), {"data": payload_data})
    return {
        "message":  f"Credencial do consumidor '{cred.consumer}' gravada com sucesso",
        "path":     _consumer_path(cred.consumer),
    }


@router.get("/consumer/{consumer}",
            summary="Lê credencial de um consumidor da API")
async def read_consumer(consumer: str):
    """
    Retorna a API Key e scopes do consumidor.
    Usado pelo SharedFlow de validação de entrada.
    """
    result = await vault_get(_consumer_path(consumer))
    data = result.get("data", {}).get("data", {})
    return {
        "consumer":   consumer,
        "api_key":    data.get("api_key"),
        "scopes":     data.get("scopes", []),
        "description": data.get("description"),
    }


# ── sharedflow context ─────────────────────────────────────────────────────

@router.post("/sharedflow/{context}", status_code=201,
             summary="Grava credencial no contexto de um SharedFlow")
async def write_sharedflow(context: str, cred: SharedFlowCredential):
    """
    Grava um bloco de dados associado a um SharedFlow específico.
    Permite que cada SharedFlow tenha seu próprio namespace de segredos.
    """
    await vault_post(_sharedflow_path(context), {"data": cred.data})
    return {
        "message": f"Credencial do SharedFlow '{context}' gravada com sucesso",
        "path":    _sharedflow_path(context),
    }


@router.get("/sharedflow/{context}",
            summary="Lê credencial no contexto de um SharedFlow")
async def read_sharedflow(context: str):
    """
    Retorna os dados do contexto do SharedFlow.
    O SharedFlow chama este endpoint via Service Callout antes de executar.
    """
    result = await vault_get(_sharedflow_path(context))
    data = result.get("data", {}).get("data", {})
    return {
        "context": context,
        "data":    data,
    }
