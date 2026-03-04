"""
humanroot.server.app
---------------------
FastAPI server exposing the HumanRoot DRC API.

Routes:
  POST   /drc/issue           Issue a root DRC
  POST   /drc/sub-delegate    Sub-delegate from an existing DRC
  GET    /drc/{drc_id}        Fetch a DRC
  GET    /drc/{drc_id}/chain  Reconstruct the full chain
  POST   /drc/revoke          Revoke a DRC (cascades to children)
  GET    /drc/{drc_id}/status Check revocation status
  GET    /drcs                List DRCs (filter by human_id or agent_id)
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from humanroot import delegate, sub_delegate, reconstruct_chain
from humanroot.chain import DelegationError
from server.db import init_db, save_drc, load_drc, list_drcs
from server.revocation import revoke, is_revoked, get_revocation


# ---------------------------------------------------------------------------
# Pydantic request models (FastAPI needs these for JSON body parsing)
# ---------------------------------------------------------------------------

class IssueDRCBody(BaseModel):
    human_id: str
    agent_id: str
    scopes: list[str]
    expires_in: str = "24h"
    provider: str = "custom"
    identity_method: str = "email"
    max_delegation_depth: int = 3
    constraints: dict = {}
    revocation_endpoint: str | None = None


class SubDelegateBody(BaseModel):
    parent_drc_id: str
    agent_id: str
    scopes: list[str]
    expires_in: str = "1h"
    provider: str = "custom"
    constraints: dict = {}


class RevokeBody(BaseModel):
    drc_id: str
    reason: str | None = None


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="HumanRoot API",
    description="Delegation Root Certificate for Autonomous Agents",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard at /dashboard
import os as _os
_dashboard = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "dashboard")
if _os.path.isdir(_dashboard):
    app.mount("/dashboard", StaticFiles(directory=_dashboard, html=True), name="dashboard")




# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/drc/issue", status_code=201)
def issue_drc(body: IssueDRCBody):
    """Issue a root DRC for a human→agent delegation."""
    try:
        drc = delegate(
            human_id=body.human_id,
            agent_id=body.agent_id,
            scopes=body.scopes,
            expires_in=body.expires_in,
            provider=body.provider,
            identity_method=body.identity_method,
            max_delegation_depth=body.max_delegation_depth,
            constraints=body.constraints,
            revocation_endpoint=body.revocation_endpoint,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    drc_dict = drc.to_dict()
    save_drc(drc_dict)
    return drc_dict


@app.post("/drc/sub-delegate", status_code=201)
def sub_delegate_drc(body: SubDelegateBody):
    """Create a child DRC from an existing DRC."""
    parent_dict = load_drc(body.parent_drc_id)
    if not parent_dict:
        raise HTTPException(status_code=404, detail="Parent DRC not found")

    if is_revoked(body.parent_drc_id):
        raise HTTPException(status_code=403, detail="Parent DRC is revoked")

    parent = _dict_to_drc(parent_dict)

    # Parse expires_in relative to now
    from humanroot.delegate import _parse_duration
    expires_at = datetime.now(timezone.utc) + _parse_duration(body.expires_in)

    try:
        child = sub_delegate(
            parent,
            agent_id=body.agent_id,
            scopes=body.scopes,
            expires_at=expires_at,
            provider=body.provider,
            constraints=body.constraints,
        )
    except DelegationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    child_dict = child.to_dict()
    save_drc(child_dict)
    return child_dict


@app.get("/drc/{drc_id}")
def get_drc(drc_id: str):
    """Fetch a single DRC by ID."""
    drc_dict = load_drc(drc_id)
    if not drc_dict:
        raise HTTPException(status_code=404, detail="DRC not found")
    drc_dict["revoked"] = is_revoked(drc_id)
    return drc_dict


@app.get("/drc/{drc_id}/chain")
def get_chain(drc_id: str):
    """Reconstruct the full delegation chain up to the root."""
    leaf_dict = load_drc(drc_id)
    if not leaf_dict:
        raise HTTPException(status_code=404, detail="DRC not found")

    # Build a local store from DB
    store = {}
    current_dict = leaf_dict
    while True:
        cid = current_dict["drc_id"]
        store[cid] = _dict_to_drc(current_dict)
        parent_id = current_dict.get("parent_drc_id")
        if not parent_id:
            break
        parent_dict = load_drc(parent_id)
        if not parent_dict:
            raise HTTPException(status_code=404, detail=f"Missing DRC in chain: {parent_id}")
        current_dict = parent_dict

    try:
        chain = reconstruct_chain(store[drc_id], store)
    except DelegationError as e:
        raise HTTPException(status_code=422, detail=str(e))

    return {
        "length": len(chain),
        "chain": [d.to_dict() for d in chain],
        "any_revoked": any(is_revoked(d.drc_id) for d in chain),
    }


@app.post("/drc/revoke")
def revoke_drc(body: RevokeBody):
    """Revoke a DRC and all its descendants."""
    if not load_drc(body.drc_id):
        raise HTTPException(status_code=404, detail="DRC not found")
    revoked_ids = revoke(body.drc_id, reason=body.reason)
    return {"revoked": revoked_ids, "count": len(revoked_ids)}


@app.get("/drc/{drc_id}/status")
def check_status(drc_id: str):
    """Check revocation status of a DRC."""
    if not load_drc(drc_id):
        raise HTTPException(status_code=404, detail="DRC not found")
    rev = get_revocation(drc_id)
    return {
        "drc_id": drc_id,
        "revoked": rev is not None,
        "revocation": rev,
    }


@app.get("/drcs")
def list_all_drcs(human_id: str | None = None, agent_id: str | None = None):
    """List DRCs, optionally filtered by human_id or agent_id."""
    drcs = list_drcs(human_id=human_id, agent_id=agent_id)
    for d in drcs:
        d["revoked"] = is_revoked(d["drc_id"])
    return {"count": len(drcs), "drcs": drcs}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _dict_to_drc(d: dict):
    """Reconstruct a DRC dataclass from a stored dict."""
    from humanroot.models import (
        DelegationRootCertificate, Principal, AgentRef, Authority
    )
    from datetime import datetime
    return DelegationRootCertificate(
        version=d["version"],
        drc_id=d["drc_id"],
        issued_at=datetime.fromisoformat(d["issued_at"]),
        expires_at=datetime.fromisoformat(d["expires_at"]),
        principal=Principal(**d["principal"]),
        agent=AgentRef(**d["agent"]),
        authority=Authority(**d["authority"]),
        revocation_endpoint=d.get("revocation_endpoint"),
        parent_drc_id=d.get("parent_drc_id"),
        root_hash=d.get("root_hash"),
        signature=d.get("signature"),
    )
