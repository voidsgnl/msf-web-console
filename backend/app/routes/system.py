import socket

from fastapi import APIRouter, HTTPException

from app.msf_rpc import rpc, MsfRpcError

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
def status():
    """Health check used by the frontend on load to confirm msfrpcd is reachable."""
    try:
        version = rpc.call("core.version")
        return {"connected": True, "version": version}
    except MsfRpcError as exc:
        return {"connected": False, "error": str(exc)}


@router.get("/network-context")
def network_context(target: str):
    """Resolve the local source address the OS would use to reach a target.

    A UDP connect selects a route and source address without sending a packet.
    This lets the UI suggest a route-appropriate LHOST while keeping the
    actual module execution an explicit user action.
    """
    target = target.strip()
    if not target:
        raise HTTPException(400, "target is required")

    try:
        addresses = socket.getaddrinfo(target, None, type=socket.SOCK_DGRAM)
    except OSError as exc:
        return {"target": target, "local_ip": None, "error": str(exc)}

    for family, socktype, proto, _canonname, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        try:
            with socket.socket(family, socktype, proto) as probe:
                probe.connect((sockaddr[0], 1))
                local_ip = probe.getsockname()[0]
                if local_ip and local_ip not in ("0.0.0.0", "::"):
                    return {
                        "target": target,
                        "resolved_target": sockaddr[0],
                        "local_ip": local_ip,
                        "method": "os-route-selection",
                    }
        except OSError:
            continue

    return {
        "target": target,
        "local_ip": None,
        "error": "The operating system could not determine a local route to this target.",
    }
