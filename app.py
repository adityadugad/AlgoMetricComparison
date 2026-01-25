from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from metrics import get_pqc_metrics, get_rsa_metrics, get_ecdh_metrics

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def home():
    return FileResponse("index.html")

@app.get("/metrics/pqc")
def pqc():
    return get_pqc_metrics()

@app.get("/metrics/rsa")
def rsa():
    return get_rsa_metrics()

@app.get("/metrics/ecdh")
def ecdh():
    return get_ecdh_metrics()
