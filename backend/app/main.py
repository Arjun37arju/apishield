from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.targets import router as targets_router
from app.core.settings import settings

app = FastAPI(title="APIShield")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_origin],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type"],
)

app.include_router(targets_router)


@app.get("/health")
def health():
    return {"status": "ok"}
