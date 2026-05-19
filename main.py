from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.vault_client import get_resource_server_config, verify_jwt
from routers import faturas_router, faturas_seed, extrato_router, portabilidade_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.resource_server_config = get_resource_server_config()
    from routers.portabilidade_router import _load_ca_cert
    from routers.extrato_router import _load_api_key
    _load_ca_cert()
    _load_api_key()
    yield


app = FastAPI(
    title="VaultFone Resource Server",
    description="Backend passivo protegido por JWT emitido e gerenciado pelo Apigee X",
    version="3.2.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def jwt_validation_middleware(request: Request, call_next):
    if request.url.path == "/health" or request.url.path.startswith("/docs") or request.url.path.startswith("/openapi"):
        return await call_next(request)

    if request.url.path.startswith("/faturas"):
        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Token ausente — use Authorization: Bearer <token>"},
            )

        token = authorization[7:]
        config = request.app.state.resource_server_config

        try:
            claims = verify_jwt(token, config)
        except ValueError as exc:
            return JSONResponse(status_code=401, content={"detail": str(exc)})

        request.state.jwt_claims = claims

    # /extrato/*       — validação da x-api-key acontece dentro do extrato_router
    # /portabilidade/* — validação do cert mTLS acontece dentro do portabilidade_router

    return await call_next(request)


app.include_router(faturas_router.router,        prefix="/faturas",        tags=["Resource Server — Faturas Telecom"])
app.include_router(faturas_seed.router,          prefix="/faturas",        tags=["Demo — Seed"])
app.include_router(extrato_router.router,        prefix="/extrato",        tags=["Resource Server — Extrato (Cenário d)"])
app.include_router(portabilidade_router.router,  prefix="/portabilidade",  tags=["Resource Server — Portabilidade (Cenário b)"])


@app.get("/health", tags=["Infra"])
def health():
    return {"status": "ok"}

@app.get("/debug/extrato-key", tags=["Infra"])
def debug_extrato_key():
    import time
    from routers.extrato_router import _key_cache
    key = _key_cache.get("key") or ""
    return {
        "key_prefix": key[:8] if key else None,
        "key_age_seconds": int(time.monotonic() - _key_cache.get("fetched_at", 0)),
    }

