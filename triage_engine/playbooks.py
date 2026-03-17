"""Incident-response playbooks and pivot guidance."""

from __future__ import annotations

from typing import Dict, List

from models.event_model import Incident


DEFAULT_PLAYBOOK = {
    "containment_guidance": [
        "Preserve evidence before making irreversible changes on the affected host.",
        "Limit attacker access by isolating impacted hosts or restricting administrative channels.",
    ],
    "scope_next": [
        "Pivot on the user, host, source IP, and process across the rest of the case.",
        "Review adjacent raw events and any linked findings for precursor or follow-on activity.",
    ],
    "validation_steps": [
        "Confirm the triggering evidence is not expected administrative activity.",
        "Validate the activity against endpoint, network, or identity telemetry if available.",
    ],
}

PLAYBOOKS: Dict[str, Dict[str, List[str]]] = {
    "powershell_backdoor_provisioning": {
        "containment_guidance": [
            "Disable the created account and remove unauthorized scheduled tasks or startup persistence.",
            "Block the remote IP or URL used to stage the payload and isolate the host if execution is ongoing.",
        ],
        "scope_next": [
            "Search for the same remote URL, script block, created username, and task name across other hosts.",
            "Review PowerShell Operational and Sysmon telemetry for follow-on execution and lateral movement.",
        ],
        "validation_steps": [
            "Verify whether the scheduled task and local user were created through an approved automation workflow.",
            "Confirm the script block content and payload path match the host state on disk.",
        ],
    },
    "local_admin_account_persistence": {
        "containment_guidance": [
            "Disable or remove unauthorized local accounts and remove them from privileged local groups.",
            "Restrict remote administrative access to the host until the account change path is understood.",
        ],
        "scope_next": [
            "Check for the same username, SAM path, and local group changes on peer hosts.",
            "Review who initiated the account creation and any adjacent process or registry activity.",
        ],
        "validation_steps": [
            "Confirm the local account was not part of a sanctioned build or provisioning workflow.",
            "Validate current local Administrators membership and compare it with a known-good baseline.",
        ],
    },
    "correlated_attack_chain": {
        "containment_guidance": [
            "Prioritize the host and identities at the center of the chain for containment.",
            "Preserve additional telemetry before clearing services, tasks, or accounts tied to the chain.",
        ],
        "scope_next": [
            "Follow the ordered evidence chain to identify entry point, execution path, and later stages.",
            "Correlate the same source IPs, services, or process names across additional hosts in the case.",
        ],
        "validation_steps": [
            "Confirm the chain timing and tactic progression are not explained by a maintenance window.",
            "Validate the most critical steps with raw events and any available EDR or network evidence.",
        ],
    },
}


def recommended_pivots(incident: Incident) -> List[str]:
    pivots: List[str] = []
    for etype, value in (
        ("host", incident.host),
        ("user", incident.user),
        ("ip", incident.source_ip),
        ("process", incident.process),
        ("service", incident.service),
    ):
        clean = str(value or "").strip()
        if clean and clean != "-":
            pivots.append(f"{etype}:{clean}")
    return pivots


def why_flagged(incident: Incident) -> str:
    if incident.evidence_chain:
        return (
            f"{incident.title} was promoted because {len(incident.evidence_chain)} corroborating evidence step(s) "
            "were linked into a single incident narrative."
        )
    return f"{incident.title} was promoted due to correlated suspicious behavior in the case."


def apply_playbook(incident: Incident) -> None:
    playbook = PLAYBOOKS.get(incident.incident_type, DEFAULT_PLAYBOOK)
    incident.containment_guidance = list(playbook.get("containment_guidance", DEFAULT_PLAYBOOK["containment_guidance"]))
    incident.scope_next = list(playbook.get("scope_next", DEFAULT_PLAYBOOK["scope_next"]))
    incident.validation_steps = list(playbook.get("validation_steps", DEFAULT_PLAYBOOK["validation_steps"]))
    incident.recommended_pivots = recommended_pivots(incident)
    incident.why_flagged = why_flagged(incident)

