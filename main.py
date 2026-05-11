from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import secrets

app = FastAPI()
security = HTTPBasic()

USERNAME = "demo_user"
PASSWORD = "demo123!"

def verificar_auth(credentials: HTTPBasicCredentials = Depends(security)):
    user_ok = secrets.compare_digest(credentials.username, USERNAME)
    pass_ok = secrets.compare_digest(credentials.password, PASSWORD)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="Não autorizado")
    return credentials.username

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/dados")
def dados(user: str = Depends(verificar_auth)):
    return {
        "mensagem": "sucesso!",
        "usuario": user,
        "dados": {"produto": "API Demo", "versao": "1.0"}
    }
