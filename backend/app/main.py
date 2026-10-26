from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routes import console, db, jobs, modules, sessions, system

app = FastAPI(title="MSF Web Console API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router)
app.include_router(modules.router)
app.include_router(sessions.router)
app.include_router(db.router)
app.include_router(jobs.router)
app.include_router(console.router)


@app.get("/")
def root():
    return {"name": "MSF Web Console API", "docs": "/docs"}
