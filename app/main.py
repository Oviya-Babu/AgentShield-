"""Main FastAPI application for AgentShield MCP Security Gateway."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.api.routes import router
from app.services.seed import seed_all

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize with seeded fixtures
    seed_all()
    yield

app = FastAPI(
    title="AgentShield MCP Security Gateway",
    description="Dynamic Trust Verification and Context-Continuous Runtime Security Enforcement for Multi-Agent MCP Systems",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes under /api
app.include_router(router, prefix="/api")

@app.get("/")
async def root():
    return {
        "name": "AgentShield MCP Security Gateway API",
        "version": "1.0.0",
        "docs_url": "/docs",
        "api_prefix": "/api"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
