"""Cyber-Agent FastAPI Core Entrypoint."""
from fastapi import FastAPI
from app.api.ingest import router as ingest_router
from app.api.dashboard import router as dashboard_router

app = FastAPI(
    title="Cyber-Agent POPIA S22 Platform",
    description="Automated incident triage, remediation playbooks, and statutory regulator reporting.",
    version="0.1.0",
)

app.include_router(ingest_router)
app.include_router(dashboard_router)

@app.get("/")
def root():
    return {
        "status": "OPERATIONAL",
        "jurisdiction": "ZA (POPIA Act 4 of 2013)",
        "dashboard": "/dashboard",
        "docs": "/docs",
    }
