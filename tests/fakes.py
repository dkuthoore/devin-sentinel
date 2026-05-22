"""Test doubles for Devin and GitHub clients (no live API calls)."""

from __future__ import annotations

import json
from typing import Any

from orchestrator.config import settings
from orchestrator.models import SessionType

AUDIT_SESSION_ID = "devin-audit-test"
REMEDIATION_SESSION_IDS = ("devin-rem-1", "devin-rem-2", "devin-rem-3")

SAMPLE_AUDIT_FINDINGS = [
    {
        "cve_id": "CVE-2026-45409",
        "package": "idna",
        "current_version": "3.10",
        "fix_versions": ["3.15"],
        "description": "Test audit finding.",
        "github_issue_url": f"https://github.com/{settings.github_repo}/issues/201",
        "github_issue_number": 201,
    },
    {
        "cve_id": "CVE-2026-44307",
        "package": "mako",
        "current_version": "1.3.11",
        "fix_versions": ["1.3.12"],
        "description": "Test audit finding.",
        "github_issue_url": f"https://github.com/{settings.github_repo}/issues/202",
        "github_issue_number": 202,
    },
    {
        "cve_id": "CVE-2026-44431",
        "package": "urllib3",
        "current_version": "2.6.3",
        "fix_versions": ["2.7.0"],
        "description": "Test audit finding.",
        "github_issue_url": f"https://github.com/{settings.github_repo}/issues/203",
        "github_issue_number": 203,
    },
]

_issue_counter = 100
_pr_counter = 900
_branch_heads: dict[str, str] = {}
_session_state: dict[str, str] = {}


def reset_fakes() -> None:
    global _issue_counter, _pr_counter
    _issue_counter = 100
    _pr_counter = 900
    _branch_heads.clear()
    _session_state.clear()


def make_issue(
    *,
    cve_id: str = "CVE-TEST",
    package: str = "pkg",
    number: int | None = None,
) -> dict[str, Any]:
    global _issue_counter
    num = number if number is not None else _issue_counter
    _issue_counter = max(_issue_counter, num + 1)
    return {
        "number": num,
        "title": f"[SECURITY] {cve_id}: {package}",
        "body": f"CVE {cve_id}",
        "labels": [{"name": "cve"}],
        "html_url": f"https://github.com/{settings.github_repo}/issues/{num}",
        "state": "open",
    }


def make_pr(*, issue_number: int, number: int | None = None, url: str | None = None) -> dict[str, Any]:
    global _pr_counter
    num = number if number is not None else _pr_counter
    _pr_counter = max(_pr_counter, num + 1)
    pr_url = url or f"https://github.com/{settings.github_repo}/pull/{num}"
    return {
        "number": num,
        "html_url": pr_url,
        "body": f"Closes #{issue_number}",
        "merged_at": None,
        "state": "open",
    }


def set_branch_head(branch: str, sha: str) -> None:
    _branch_heads[branch] = sha


def get_branch_head(branch: str | None = None) -> str | None:
    ref = branch or settings.github_default_branch
    return _branch_heads.get(ref, "sha-initial-seed")


def fake_create_session(prompt: str, session_type: SessionType) -> dict[str, Any]:
    if session_type == SessionType.AUDIT:
        session_id = AUDIT_SESSION_ID
    else:
        idx = sum(1 for sid in _session_state if sid.startswith("devin-rem"))
        session_id = REMEDIATION_SESSION_IDS[min(idx, len(REMEDIATION_SESSION_IDS) - 1)]
    _session_state[session_id] = "running"
    return {
        "session_id": session_id,
        "url": f"https://app.devin.ai/sessions/{session_id}",
        "status": "running",
    }


def fake_get_session(session_id: str) -> dict[str, Any]:
    state = _session_state.get(session_id, "finished")
    if state == "running":
        return {
            "session_id": session_id,
            "status": "running",
            "messages": ["Working..."],
            "devin_messages": ["Working..."],
        }

    if session_id == AUDIT_SESSION_ID:
        return {
            "session_id": session_id,
            "status": "finished",
            "messages": [f"AUDIT_DONE: {json.dumps(SAMPLE_AUDIT_FINDINGS)}"],
            "devin_messages": [f"AUDIT_DONE: {json.dumps(SAMPLE_AUDIT_FINDINGS)}"],
        }

    if session_id in REMEDIATION_SESSION_IDS:
        pr_number = 500 + list(REMEDIATION_SESSION_IDS).index(session_id) + 1
    else:
        pr_number = 501
    pr_url = f"https://github.com/{settings.github_repo}/pull/{pr_number}"
    return {
        "session_id": session_id,
        "status": "finished",
        "messages": [f"DONE: {pr_url}"],
        "devin_messages": [f"DONE: {pr_url}"],
    }


def advance_all_sessions() -> None:
    for session_id in list(_session_state):
        _session_state[session_id] = "finished"


def advance_session(session_id: str) -> None:
    _session_state[session_id] = "finished"
