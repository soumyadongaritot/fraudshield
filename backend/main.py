from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ml_model import predict_url

app = FastAPI(title="FraudShield API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def root():
    return {"status": "FraudShield API v3.0 running"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/check")
def check_url(request: URLRequest):
    return predict_url(request.url)

@app.options("/check")
def options_check():
    return {"status": "ok"}