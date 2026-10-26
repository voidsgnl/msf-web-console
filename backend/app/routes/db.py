from fastapi import APIRouter, HTTPException

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/db", tags=["database"])


@router.get("/hosts")
def hosts():
    try:
        return rpc.call("db.hosts", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/services")
def services():
    try:
        return rpc.call("db.services", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/vulns")
def vulns():
    try:
        return rpc.call("db.vulns", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/loot")
def loot():
    try:
        return rpc.call("db.loots", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/creds")
def creds():
    try:
        return rpc.call("db.creds", {})
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))


@router.get("/workspaces")
def workspaces():
    try:
        return rpc.call("db.workspaces")
    except MsfRpcError as exc:
        raise HTTPException(502, str(exc))
