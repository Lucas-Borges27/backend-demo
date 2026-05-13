from fastapi import FastAPI
from routers import auth_router, kv_router, kvm_router, transit_router, pki_router

app = FastAPI(
    title="Vault Bridge API — Apigee X",
    description="Integração HashiCorp Vault para os casos de uso Apigee X",
    version="2.0.0",
)

# ── routers originais ──────────────────────────────────────────────
app.include_router(auth_router.router, prefix="/auth",    tags=["Auth (usuários)"])

# ── casos de uso Apigee X ─────────────────────────────────────────
app.include_router(kv_router.router,      prefix="/kv",      tags=["KV — credenciais de backends"])
app.include_router(kvm_router.router,     prefix="/kvm",      tags=["KVM — rotação de API Keys"])
app.include_router(transit_router.router, prefix="/transit",  tags=["Transit — JWT signing"])
app.include_router(pki_router.router,     prefix="/pki",      tags=["PKI — mTLS certificates"])


@app.get("/health", tags=["Infra"])
def health():
    return {"status": "ok"}


@app.get("/debug", tags=["Infra"])
def debug():
    from core.vault_client import VAULT_ADDR, VAULT_NS, VAULT_MOUNT, VAULT_ROLE_ID, VAULT_SECRET_ID
    return {
        "VAULT_ADDR":      VAULT_ADDR,
        "VAULT_NS":        VAULT_NS,
        "VAULT_MOUNT":     VAULT_MOUNT,
        "ROLE_ID_SET":     bool(VAULT_ROLE_ID),
        "SECRET_ID_SET":   bool(VAULT_SECRET_ID),
    }
