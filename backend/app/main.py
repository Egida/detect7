import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import SessionLocal
from .routers import auth, dashboard, domains
from .seed import seed_plans

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")


@asynccontextmanager
async def lifespan(application: FastAPI):
    db = SessionLocal()
    try:
        seed_plans(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="Detect7 Service API",
    version="0.1.0",
    description="Public-facing SaaS API for Detect7 L7 DDoS analytics.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(dashboard.router)


@app.get("/health")
def health():
    return {"status": "ok"}
