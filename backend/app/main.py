from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import Base, engine
from .routers import auth, dashboard, domains


Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Detect7 Service API",
    version="0.1.0",
    description="Public-facing SaaS API for Detect7 L7 DDoS analytics.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(domains.router)
app.include_router(dashboard.router)


@app.get("/health")
def health():
    return {"status": "ok"}
