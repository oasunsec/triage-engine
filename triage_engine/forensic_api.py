"""Evidence explorer and evidence-link review routes, kept out of server.py.

Routes read fixed case files only (never a path derived from evidence or a
request), enforce the existing roles, and rely on the server's CSRF
middleware for state-changing methods. Analyst decisions are stored in the
review store; engine output files are never modified.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from triage_engine.review_store import (
    LINK_DECISIONS,
    add_analyst_evidence_link,
    get_evidence_link_reviews,
    get_history,
    list_analyst_evidence_links,
    update_analyst_evidence_link,
    upsert_evidence_link_review,
)

_RELATIONSHIP_ID = re.compile(r"^rel_[0-9a-f]{64}$")
_OBSERVATION_ID = re.compile(r"^obs_[0-9a-f]{64}$")
_LINK_ID = re.compile(r"^hyp_[0-9a-f]{32}$")
MAX_PAGE = 2000


class LinkReviewUpdate(BaseModel):
    decision: str = Field(..., description=f"One of: {', '.join(LINK_DECISIONS)}")
    rationale: str = Field("", max_length=4000)


class AnalystLinkCreate(BaseModel):
    source_observation_id: str
    target_observation_id: str
    claim: str = Field(..., min_length=1, max_length=2000)


def _read_json(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def _event_observation_exists(case_path: str, observation_id: str) -> bool:
    path = os.path.join(case_path, "raw_events.jsonl")
    if not os.path.isfile(path):
        return False
    needle = f'"observation_id": "{observation_id}"'
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if observation_id in line and (needle in line or json.loads(line).get("observation_id") == observation_id):
                return True
    return False


def build_forensics_router(*, require_user: Callable, require_case: Callable, audit_case_access: Callable,
                           record_audit_event: Callable, redact: Callable) -> APIRouter:
    router = APIRouter(tags=["Forensics"])

    def case_files(case_name: str) -> tuple[str, str]:
        case_path = require_case(case_name)
        return case_path, os.path.basename(case_path)

    @router.get("/api/cases/{case_name}/forensic-observations",
                summary="List Forensic Observations",
                description="Page through artifact observations with their source locators and time semantics.")
    def list_observations(case_name: str, request: Request, offset: int = Query(0, ge=0),
                          limit: int = Query(200, ge=1, le=MAX_PAGE), kind: str = "", q: str = Query("", max_length=256)):
        user = require_user(request, ("viewer", "analyst", "admin"))
        case_path, resolved = case_files(case_name)
        payload = _read_json(os.path.join(case_path, "forensic_observations.json"))
        observations = payload.get("observations", []) or []
        query = q.strip().casefold()
        rows = [item for item in observations if (not kind or item.get("kind") == kind)
                and (not query or query in json.dumps(item, sort_keys=True).casefold())]
        audit_case_access(user, case_name=resolved, endpoint="/api/cases/{case_name}/forensic-observations")
        return redact({"summary": payload.get("summary", {}), "representation": payload.get("representation", ""),
                       "total": len(rows), "offset": offset, "observations": rows[offset:offset + limit],
                       "kinds": sorted({item.get("kind", "") for item in observations})})

    @router.get("/api/cases/{case_name}/evidence-links",
                summary="List Evidence Links",
                description="Derived event-to-artifact links with analyst decisions, analyst hypotheses, and source coverage.")
    def list_links(case_name: str, request: Request, offset: int = Query(0, ge=0),
                   limit: int = Query(500, ge=1, le=MAX_PAGE), link_class: str = ""):
        user = require_user(request, ("viewer", "analyst", "admin"))
        case_path, resolved = case_files(case_name)
        payload = _read_json(os.path.join(case_path, "evidence_relationships.json"))
        relationships = payload.get("relationships", []) or []
        reviews = get_evidence_link_reviews(resolved)
        current = {item.get("relationship_id") for item in relationships}
        rows = [{**item, "review": reviews.get(item.get("relationship_id"), {"decision": "unreviewed"})}
                for item in relationships if not link_class or item.get("link_class") == link_class]
        audit_case_access(user, case_name=resolved, endpoint="/api/cases/{case_name}/evidence-links")
        return redact({
            "schema_version": payload.get("schema_version", ""), "summary": payload.get("summary", {}),
            "link_classes": payload.get("link_classes", []), "decisions": list(LINK_DECISIONS),
            "total": len(rows), "offset": offset, "relationships": rows[offset:offset + limit],
            # Decisions about links that a rerun no longer produces stay visible rather than vanishing.
            "orphaned_reviews": [review for key, review in sorted(reviews.items()) if key not in current],
            "analyst_links": [{**link, "link_class": "analyst_hypothesis"} for link in list_analyst_evidence_links(resolved)],
        })

    @router.patch("/api/cases/{case_name}/evidence-links/{relationship_id}/review",
                  summary="Review Evidence Link",
                  description="Confirm, reject, or flag a derived evidence link. The derived link itself is unchanged.")
    def review_link(case_name: str, relationship_id: str, body: LinkReviewUpdate, request: Request):
        user = require_user(request, ("analyst", "admin"))
        case_path, resolved = case_files(case_name)
        if not _RELATIONSHIP_ID.fullmatch(relationship_id):
            raise HTTPException(400, "Invalid relationship id")
        if body.decision not in LINK_DECISIONS:
            raise HTTPException(400, f"Invalid decision. Must be one of: {', '.join(LINK_DECISIONS)}")
        relationships = _read_json(os.path.join(case_path, "evidence_relationships.json")).get("relationships", []) or []
        if relationship_id not in {item.get("relationship_id") for item in relationships}:
            raise HTTPException(404, "Evidence link not found in the current analysis")
        review = upsert_evidence_link_review(resolved, relationship_id, decision=body.decision,
                                             rationale=body.rationale, changed_by=user["username"])
        record_audit_event(actor_username=user["username"], action="review_evidence_link", target_username=resolved,
                           details={"case_name": resolved, "relationship_id": relationship_id, "decision": body.decision})
        return review

    @router.get("/api/cases/{case_name}/evidence-links/{link_id}/history", summary="Evidence Link History")
    def link_history(case_name: str, link_id: str, request: Request):
        user = require_user(request, ("viewer", "analyst", "admin"))
        _, resolved = case_files(case_name)
        if not (_RELATIONSHIP_ID.fullmatch(link_id) or _LINK_ID.fullmatch(link_id)):
            raise HTTPException(400, "Invalid link id")
        audit_case_access(user, case_name=resolved, endpoint="/api/cases/{case_name}/evidence-links/{link_id}/history")
        return {"history": get_history(resolved, "evidence_link", link_id)}

    @router.post("/api/cases/{case_name}/evidence-links/hypotheses",
                 summary="Add Analyst Hypothesis Link",
                 description="Record an analyst-asserted link between two observations in this case, labelled analyst_hypothesis.")
    def add_hypothesis(case_name: str, body: AnalystLinkCreate, request: Request):
        user = require_user(request, ("analyst", "admin"))
        case_path, resolved = case_files(case_name)
        ids = (body.source_observation_id, body.target_observation_id)
        if not all(_OBSERVATION_ID.fullmatch(value) for value in ids) or ids[0] == ids[1]:
            raise HTTPException(400, "Two different observation ids are required")
        artifacts = {item.get("id") for item in
                     _read_json(os.path.join(case_path, "forensic_observations.json")).get("observations", []) or []}
        for value in ids:
            if value not in artifacts and not _event_observation_exists(case_path, value):
                raise HTTPException(404, f"Observation not found in this case: {value}")
        link = add_analyst_evidence_link(resolved, link_id="hyp_" + uuid.uuid4().hex, source_observation_id=ids[0],
                                         target_observation_id=ids[1], claim=body.claim.strip(),
                                         created_by=user["username"])
        record_audit_event(actor_username=user["username"], action="add_evidence_hypothesis", target_username=resolved,
                           details={"case_name": resolved, "link_id": link["link_id"]})
        return {**link, "link_class": "analyst_hypothesis"}

    @router.patch("/api/cases/{case_name}/evidence-links/hypotheses/{link_id}",
                  summary="Review Analyst Hypothesis Link")
    def review_hypothesis(case_name: str, link_id: str, body: LinkReviewUpdate, request: Request):
        user = require_user(request, ("analyst", "admin"))
        _, resolved = case_files(case_name)
        if not _LINK_ID.fullmatch(link_id):
            raise HTTPException(400, "Invalid hypothesis id")
        if body.decision not in LINK_DECISIONS:
            raise HTTPException(400, f"Invalid decision. Must be one of: {', '.join(LINK_DECISIONS)}")
        link = update_analyst_evidence_link(resolved, link_id, decision=body.decision, rationale=body.rationale,
                                            changed_by=user["username"])
        if link is None:
            raise HTTPException(404, "Hypothesis link not found")
        record_audit_event(actor_username=user["username"], action="review_evidence_hypothesis", target_username=resolved,
                           details={"case_name": resolved, "link_id": link_id, "decision": body.decision})
        return {**link, "link_class": "analyst_hypothesis"}

    return router
