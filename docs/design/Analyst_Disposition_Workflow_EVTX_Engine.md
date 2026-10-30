# Analyst Disposition and Case Review Layer
## Workflow Maturity Upgrade for the EVTX Detection Engine

---

# Purpose

This document defines the analyst disposition and review workflow that should be added to the EVTX detection engine.

The engine already supports:

- EVTX parsing
- behavioral detection
- signal correlation
- findings
- incidents
- timelines
- entity graphs
- case reports

The missing maturity layer is analyst review.

This feature makes the platform look and behave more like a real detection engineering and SOC investigation system.

It adds the ability to:

- assign ownership
- track review status
- record analyst decisions
- capture investigation notes
- feed triage outcomes back into tuning

This closes the loop:

detect → investigate → decide → document → improve

---

# Why This Feature Matters

A strong detection engine can identify suspicious activity.

A mature security platform must also answer:

- Was this real?
- Who reviewed it?
- What decision was made?
- What evidence supported that decision?
- Does the rule need tuning?

Without this layer, detections remain technically strong but operationally incomplete.

With this layer, the platform supports a realistic analyst workflow.

---

# Design Goals

The analyst disposition system should:

- work for both findings and incidents
- preserve an audit trail
- support case ownership
- support triage status tracking
- store investigation notes
- allow feedback to improve suppressions and rules
- remain simple and lightweight

This should not become a full ticketing system.

The goal is a clean review layer for a detection platform.

---

# Workflow Model

The analyst workflow should follow this sequence:

Detection generated
↓
Analyst opens case
↓
Analyst reviews incident or finding
↓
Analyst sets status
↓
Analyst sets disposition
↓
Analyst records notes
↓
Analyst closes or escalates case
↓
Tuning feedback captured

---

# Core Concepts

## Status

Status represents where the review is in the workflow.

Recommended values:

Open
In Review
Escalated
Closed
Suppressed

Definitions:

- Open: newly created and not yet reviewed
- In Review: analyst is actively investigating
- Escalated: sent for deeper review or response
- Closed: triage is complete
- Suppressed: intentionally hidden or muted after review

## Disposition

Disposition represents the analyst’s decision about the detection.

Recommended values:

True Positive
False Positive
Benign Expected Activity
Suspicious - Needs More Investigation
Test / Lab Activity
Duplicate

Definitions:

- True Positive: confirmed malicious or genuinely suspicious
- False Positive: detection logic was wrong
- Benign Expected Activity: legitimate behavior that matched logic
- Suspicious - Needs More Investigation: not enough evidence yet
- Test / Lab Activity: known validation, training, or test behavior
- Duplicate: already covered by another finding or incident

## Owner

Owner identifies the current analyst or reviewer.

Examples:

tbobo
analyst1
soc-tier1
dfir-review

This field supports accountability and handoff.

## Notes

Notes store analyst reasoning.

Examples:

Confirmed audit log clearing shortly after privileged access from 20.93.113.115.
Need to validate whether this was approved admin maintenance.

Notes should be short, practical, and operational.

---

# Data Model

The review layer should be stored separately from the detection logic so core artifacts remain stable.

Recommended object structure for each finding or incident:

```json
{
  "review": {
    "status": "In Review",
    "disposition": "Suspicious - Needs More Investigation",
    "owner": "tbobo",
    "notes": [
      {
        "author": "tbobo",
        "timestamp": "2026-03-12T05:10:00Z",
        "text": "Audit log clearing occurred after remote logon from 20.93.113.115."
      },
      {
        "author": "tbobo",
        "timestamp": "2026-03-12T05:14:00Z",
        "text": "Need to compare against known maintenance activity."
      }
    ],
    "reviewed_at": "2026-03-12T05:14:00Z",
    "created_at": "2026-03-12T04:02:32Z",
    "updated_at": "2026-03-12T05:14:00Z"
  }
}
```

---

# Recommended Schema

## Finding Review Schema

```json
{
  "finding_id": "FND-0001",
  "case_id": "Checking",
  "status": "In Review",
  "disposition": "Suspicious - Needs More Investigation",
  "owner": "tbobo",
  "priority": "P1",
  "notes": [
    {
      "author": "tbobo",
      "timestamp": "2026-03-12T05:10:00Z",
      "text": "Security log was cleared by Administrator on WIN-14AGJ280HCA."
    }
  ],
  "recommended_tuning_action": null,
  "linked_incident_id": "INC-0001",
  "created_at": "2026-03-12T04:02:32Z",
  "updated_at": "2026-03-12T05:10:00Z",
  "reviewed_at": "2026-03-12T05:10:00Z"
}
```

## Incident Review Schema

```json
{
  "incident_id": "INC-0002",
  "case_id": "Checking",
  "status": "Escalated",
  "disposition": "True Positive",
  "owner": "tbobo",
  "priority": "P1",
  "notes": [
    {
      "author": "tbobo",
      "timestamp": "2026-03-12T05:18:00Z",
      "text": "Remote credential use from 20.93.113.115 followed by privileged access on bcorp-prod-srv1."
    }
  ],
  "recommended_tuning_action": "Add stronger correlation weight for explicit credential logon followed by privilege assignment.",
  "linked_finding_ids": ["FND-0002", "FND-0003"],
  "created_at": "2026-03-12T04:02:32Z",
  "updated_at": "2026-03-12T05:18:00Z",
  "reviewed_at": "2026-03-12T05:18:00Z"
}
```

---

# Storage Design

Use a simple persistent store.

Recommended options:

SQLite first
Postgres later if needed

Suggested tables:

case_reviews
finding_reviews
incident_reviews
review_notes
review_history

---

# Minimal SQLite Table Design

## finding_reviews

```sql
CREATE TABLE finding_reviews (
    finding_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL,
    disposition TEXT,
    owner TEXT,
    priority TEXT,
    recommended_tuning_action TEXT,
    linked_incident_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reviewed_at TEXT
);
```

## incident_reviews

```sql
CREATE TABLE incident_reviews (
    incident_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    status TEXT NOT NULL,
    disposition TEXT,
    owner TEXT,
    priority TEXT,
    recommended_tuning_action TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    reviewed_at TEXT
);
```

## review_notes

```sql
CREATE TABLE review_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    author TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    text TEXT NOT NULL
);
```

## review_history

```sql
CREATE TABLE review_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    timestamp TEXT NOT NULL
);
```

---

# API Design

The review layer should expose simple endpoints.

## Read review state

GET /api/cases/{case_id}/findings/{finding_id}/review
GET /api/cases/{case_id}/incidents/{incident_id}/review

## Update review state

PATCH /api/cases/{case_id}/findings/{finding_id}/review
PATCH /api/cases/{case_id}/incidents/{incident_id}/review

## Add note

POST /api/cases/{case_id}/findings/{finding_id}/notes
POST /api/cases/{case_id}/incidents/{incident_id}/notes

## List queue views

GET /api/review/queue?status=Open
GET /api/review/queue?owner=tbobo
GET /api/review/queue?disposition=False%20Positive

---

# Example PATCH Payload

```json
{
  "status": "Closed",
  "disposition": "True Positive",
  "owner": "tbobo",
  "recommended_tuning_action": "Keep current rule logic. Add additional pivot to raw logon events.",
  "reviewed_at": "2026-03-12T05:20:00Z"
}
```

---

# UI Design

The UI should be added to both Finding Detail and Incident Detail views.

## New Analyst Review Panel

Add a new section titled:

Analyst Review

Panel contents:

- Status dropdown
- Disposition dropdown
- Owner text field or dropdown
- Notes text area
- Save button
- Review history link
- Last updated timestamp

---

# Suggested Finding Detail Layout

```text
--------------------------------------------------
Finding Title
Severity | Confidence | Host | Technique
--------------------------------------------------
Why Flagged
Evidence Chain
Recommended Next Step
Containment Guidance
--------------------------------------------------
Analyst Review
Status: [In Review ▼]
Disposition: [Suspicious - Needs More Investigation ▼]
Owner: [tbobo]
Notes:
[ Security log cleared after privileged activity from 20.93.113.115 ]
[ Save Review ]
--------------------------------------------------
Review History
- tbobo changed status Open → In Review
- tbobo added note
--------------------------------------------------
```

# Suggested Incident Detail Layout

```text
--------------------------------------------------
Incident Title
Priority | Severity | Confidence | Affected Hosts
--------------------------------------------------
Narrative Summary
Evidence Chain
Containment Guidance
Validation Steps
--------------------------------------------------
Analyst Review
Status: [Escalated ▼]
Disposition: [True Positive ▼]
Owner: [tbobo]
Notes:
[ Confirmed suspicious remote credential use and privileged access ]
Recommended Tuning Action:
[ Add stronger weighting for explicit credential use + privilege assignment ]
[ Save Review ]
--------------------------------------------------
```

---

# Queue View

Add a review queue page or filterable table.

Suggested columns:

ID
Type
Title
Priority
Status
Disposition
Owner
Updated

Example rows:

INC-0001 | Incident | Audit log cleared | P1 | In Review | Suspicious - Needs More Investigation | tbobo | 2026-03-12
FND-0002 | Finding  | Local admin persistence | P1 | Closed | True Positive | tbobo | 2026-03-12

This makes the platform feel operational.

---

# Review History

Every review change should be recorded.

Tracked actions:

- status changed
- disposition changed
- owner assigned
- note added
- tuning action added

Example history:

2026-03-12 05:10:00 tbobo changed status from Open to In Review
2026-03-12 05:11:00 tbobo added note
2026-03-12 05:20:00 tbobo changed disposition from null to True Positive

This creates an audit trail.

---

# Tuning Feedback Loop

This is the most valuable part.

Analyst review data should be reusable for tuning.

## If disposition = False Positive

Possible actions:

- create suppression
- lower confidence
- refine threshold
- add environment-specific allow logic

## If disposition = Benign Expected Activity

Possible actions:

- add safe suppression condition
- document common benign context
- reduce priority

## If disposition = True Positive

Possible actions:

- preserve logic
- strengthen correlation
- add related pivots
- create hunt recommendation

This turns analyst review into rule improvement data.

---

# Suggested Tuning Export

Add an export or derived summary like:

```json
{
  "rule_id": "audit_log_cleared",
  "cases_reviewed": 8,
  "true_positive_count": 5,
  "false_positive_count": 1,
  "benign_expected_count": 2,
  "suggested_action": "Keep rule high severity. Add allow logic for known maintenance window."
}
```

This is very useful for detection engineering.

---

# Minimal Implementation Plan

This feature can be implemented in a practical, lightweight way.

## Phase 1

- add review schema
- add SQLite tables
- add read/update endpoints
- add notes support
- show review panel on finding and incident pages

## Phase 2

- add review queue page
- add review history
- add filtering by owner/status/disposition

## Phase 3

- add tuning feedback export
- add metrics for true positives and false positives

---

# UX Guidelines

Keep the workflow simple.

Rules:

- default new detections to Open
- allow quick status updates
- make notes easy to save
- show review state prominently
- do not hide original evidence
- keep triage actions near the incident narrative

---

# Example Realistic Usage

## Example 1 — True Positive

Incident: Remote credential attack followed by privileged access
Status: Closed
Disposition: True Positive
Owner: tbobo
Notes:
Confirmed explicit credential use from 20.93.113.115 followed by privileged access on bcorp-prod-srv1.

## Example 2 — Benign Expected Activity

Finding: Audit log cleared
Status: Closed
Disposition: Benign Expected Activity
Owner: tbobo
Notes:
Validated with admin team. Expected maintenance action during approved change window.

## Example 3 — False Positive

Finding: Rare process execution
Status: Closed
Disposition: False Positive
Owner: tbobo
Notes:
Triggered on environment-specific monitoring tool. Add suppression for signed internal binary.
Recommended Tuning Action:
Add allow condition for approved signed process hash.

---

# Why This Upgrade Is Important

This feature adds the part most personal projects miss:

analyst decision making

The engine already detects and explains.

This upgrade lets it:

- support triage
- support ownership
- capture decisions
- improve future detections

That makes the project look much closer to a real security platform.

---

# Final Recommendation

Implement this feature before adding more detectors.

The current engine already has strong detection depth.

The next maturity gain comes from:

detect → review → disposition → tune

This is the workflow that makes a strong technical engine feel enterprise-grade.

---

# Deliverable Outcome

After this feature is added, the EVTX detection engine will support:

- case management
- behavioral detections
- findings and incidents
- timelines and graphs
- raw event pivots
- analyst disposition
- investigation notes
- review history
- tuning feedback

This is the right next step for making the platform feel operational, realistic, and mature.
