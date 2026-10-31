from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.routes import assessments, auth, console, cve, db, jobs, modules, sessions, system, web_recon
from app.security import (
    AuthenticationMiddleware,
    LocalOnlyMiddleware,
    allowed_hosts,
    allowed_web_origins,
)

app = FastAPI(title="Security Assessment Platform API")

# Cookies are only sent to explicitly allowlisted browser origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_web_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=allowed_hosts(),
)
# Both checks remain active: login does not disable the local-only boundary.
app.add_middleware(LocalOnlyMiddleware)
app.add_middleware(AuthenticationMiddleware)

app.include_router(auth.router)
app.include_router(system.router)
app.include_router(web_recon.router)
app.include_router(assessments.router)
app.include_router(modules.router)
app.include_router(sessions.router)
app.include_router(db.router)
app.include_router(cve.router)
app.include_router(jobs.router)
app.include_router(console.router)


@app.get("/")
def root():
    return {
        "name": "Security Assessment Platform API",
        "docs": "/docs",
        "access": "authenticated-local-only",
        "authentication_configured": True,
    }
