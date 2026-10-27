from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.routes import console, db, jobs, modules, sessions, system
from app.security import LocalOnlyMiddleware, allowed_hosts, allowed_web_origins

app = FastAPI(title="MSF Web Console API")

# The UI is local-only until a real user authentication system is implemented.
# CORS is a browser policy, not authentication; Host validation and the client
# address guard below are separate defence-in-depth protections.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_web_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts(),
)
app.add_middleware(LocalOnlyMiddleware)

app.include_router(system.router)
app.include_router(modules.router)
app.include_router(sessions.router)
app.include_router(db.router)
app.include_router(jobs.router)
app.include_router(console.router)


@app.get("/")
def root():
    return {
        "name": "MSF Web Console API",
        "docs": "/docs",
        "access": "local-only",
        "authentication_configured": False,
    }
