import json
import logging
import re
import time
from typing import Any

import httpx
from httpx import HTTPStatusError

from orchestrator.config import settings
from orchestrator.models import CveFinding, SessionType

logger = logging.getLogger(__name__)

# Docs: https://docs.devin.ai/api-reference/getting-started/migration-guide
# Create: POST /v3/organizations/{org_id}/sessions (ManageOrgSessions)
# List:   GET  /v3/organizations/{org_id}/sessions (ViewOrgSessions)
# Get:    GET  /v3/organizations/{org_id}/sessions/{devin_id} (ViewOrgSessions)
# Messages: GET /v3/organizations/{org_id}/sessions/{devin_id}/messages (ViewOrgSessions)

# v3 SessionResponse.status values that mean Devin is still working.
ACTIVE_DEVIN_STATUSES = frozenset({"running", "claimed", "new", "resuming", "suspended"})

DONE_PATTERN = re.compile(r"DONE:\s*(https://\S+)", re.IGNORECASE)
BLOCKED_PATTERN = re.compile(r"BLOCKED:\s*(.+)", re.IGNORECASE | re.DOTALL)
AUDIT_DONE_PATTERN = re.compile(r"AUDIT_DONE:\s*(\[.*\])", re.IGNORECASE | re.DOTALL)


class DevinApiError(Exception):
    """Raised when the Devin v3 API returns a non-success response."""

    def __init__(self, status_code: int, message: str, *, context: str = "") -> None:
        self.status_code = status_code
        self.message = message
        self.context = context
        super().__init__(self.user_message())

    def user_message(self) -> str:
        prefix = f"Devin API error ({self.status_code})"
        if self.context:
            prefix = f"{prefix} [{self.context}]"
        return f"{prefix}: {self.message}"

    @classmethod
    def from_response(cls, response: httpx.Response, context: str) -> "DevinApiError":
        return cls(response.status_code, _parse_error_body(response), context=context)


def _parse_error_body(response: httpx.Response) -> str:
    text = (response.text or "").strip()
    if not text:
        return response.reason_phrase or "request failed"
    try:
        payload = response.json()
    except json.JSONDecodeError:
        return text[:500]
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
        if detail is not None:
            return json.dumps(detail)
        message = payload.get("message")
        if isinstance(message, str):
            return message
    return text[:500]


def build_audit_prompt() -> str:
    return f"""You are performing dependency security triage for Sentinel.

Repository: https://github.com/{settings.github_repo}
Target file: requirements/base.txt

Your task:
1. Clone the repository.
2. Run pip-audit against requirements/base.txt.
3. For each CVE with an available fix version, create one GitHub issue in the repository.
4. Use labels: security, cve, automated, dependencies.
5. Keep the issue body structured with CVE ID, package, current version,
   fixed version, description, file to modify, and acceptance criteria.

When the audit is complete, reply with exactly:
  AUDIT_DONE: [{{"cve_id":"...","package":"...","current_version":"...",
  "fix_versions":["..."],"description":"...","github_issue_url":"...",
  "github_issue_number":123}}]

If you are blocked and cannot proceed without human input, reply with:
  BLOCKED: <reason>
"""


def build_remediation_prompt(finding: CveFinding) -> str:
    fix_version = finding.fix_version
    issue_number = finding.github_issue_number or 0
    issue_url = finding.github_issue_url or f"https://github.com/{settings.github_repo}/issues/{issue_number}"
    branch = f"fix/{finding.cve_id.lower()}-{finding.package}"

    return f"""You are remediating a security vulnerability in Apache Superset.

## Vulnerability Details
- CVE ID: {finding.cve_id}
- Package: `{finding.package}`
- Current pinned version: `{finding.current_version}`
- Safe version: `{fix_version}` or higher
- Description: {finding.description}

## Repository
Clone this repository: https://github.com/{settings.github_repo}
Base branch: `master`
Create branch: `{branch}`

## Required Change
In `requirements/base.txt`, find the line pinning `{finding.package}` and
update it to require `>={fix_version}`.
If `requirements/base.in` exists and owns the dependency, update that too.

## Steps
1. Create the branch `{branch}`.
2. Apply the minimal dependency change.
3. Run install and focused tests that are practical for the repository.
4. Fix only downstream breakage caused by this version bump.
5. Commit with: `fix: upgrade {finding.package} to {fix_version} to remediate {finding.cve_id}`
6. Open a PR to `master` with a body that includes `Closes #{issue_number}`.
7. Reference the issue: {issue_url}

When your task is complete, reply with exactly:
  DONE: <PR_URL>

If you are blocked and cannot proceed without human input, reply with:
  BLOCKED: <reason>
"""


def _auth_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.devin_api_key}",
        "Accept": "application/json",
    }


def _json_headers() -> dict[str, str]:
    return {**_auth_headers(), "Content-Type": "application/json"}


def _require_credentials() -> None:
    if not settings.devin_api_key:
        raise RuntimeError("DEVIN_API_KEY is required")
    if not settings.devin_org_id:
        raise RuntimeError(
            "DEVIN_ORG_ID is required "
            "(find it on Devin Settings → Service users — https://docs.devin.ai/api-reference/v3/usage-examples)"
        )


def bare_devin_id(session_id: str) -> str:
    """Normalize session id for DB storage and lookup."""
    return session_id.removeprefix("devin-")


def _ensure_devin_id(session_id: str) -> str:
    """v3 path param uses devin_id with prefix devin- (docs: get-organizations-session)."""
    if session_id.startswith("devin-"):
        return session_id
    return f"devin-{session_id}"


def is_devin_session_active(session_data: dict[str, Any]) -> bool:
    """True when Devin v3 reports the session is still in flight."""
    return (session_data.get("status") or "").lower() in ACTIVE_DEVIN_STATUSES


def infer_session_type(session_data: dict[str, Any]) -> SessionType:
    """Infer audit vs remediation from Sentinel session titles."""
    title = (session_data.get("title") or "").lower()
    if "remediation" in title:
        return SessionType.REMEDIATION
    return SessionType.AUDIT


def list_organization_sessions(
    *,
    devin_session_id: str | None = None,
    created_after: int | None = None,
    origins: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    List sessions from Devin v3 (paginated).
    Docs: https://docs.devin.ai/api-reference/v3/sessions/organizations-sessions
    """
    _require_credentials()
    sessions: list[dict[str, Any]] = []
    after: str | None = None

    while True:
        params: dict[str, Any] = {"first": 100}
        if after:
            params["after"] = after
        if created_after is not None:
            params["created_after"] = created_after
        if origins:
            params["origins"] = origins
        if devin_session_id:
            params["session_ids"] = [_ensure_devin_id(devin_session_id)]

        response = httpx.get(
            _org_resource("/sessions"),
            headers=_auth_headers(),
            params=params,
            timeout=30,
        )
        if response.status_code == 422 and origins:
            params.pop("origins", None)
            response = httpx.get(
                _org_resource("/sessions"),
                headers=_auth_headers(),
                params=params,
                timeout=30,
            )
        _raise_for_response(response, "list sessions")
        payload = response.json()

        for item in payload.get("items", []):
            if isinstance(item, dict):
                sessions.append(item)

        if not payload.get("has_next_page"):
            break
        after = payload.get("end_cursor")
        if not after:
            break

    return sessions


def _session_list_cutoff_epoch() -> int:
    hours = max(1, settings.devin_session_lookback_hours)
    return int(time.time()) - hours * 3600


def list_active_devin_sessions(devin_session_id: str | None = None) -> list[dict[str, Any]]:
    """Return in-progress Devin sessions (API-created within DEVIN_SESSION_LOOKBACK_HOURS)."""
    if devin_session_id:
        data = get_session(devin_session_id)
        return [data] if is_devin_session_active(data) else []

    created_after = _session_list_cutoff_epoch()
    candidates = list_organization_sessions(created_after=created_after, origins=["api"])
    return [item for item in candidates if is_devin_session_active(item)]


def _org_resource(path: str) -> str:
    base = settings.devin_base_url.rstrip("/")
    org_id = settings.devin_org_id.strip()
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base}/organizations/{org_id}{suffix}"


def _raise_for_response(response: httpx.Response, context: str) -> None:
    try:
        response.raise_for_status()
    except HTTPStatusError:
        logger.error(
            "Devin API %s failed (%s): %s",
            context,
            response.status_code,
            response.text[:500],
        )
        raise DevinApiError.from_response(response, context) from None


def _map_v3_status(session_data: dict[str, Any]) -> str:
    """Map v3 SessionResponse.status to legacy labels used by the poller."""
    status = (session_data.get("status") or "").lower()
    detail = (session_data.get("status_detail") or "").lower()

    if status == "exit" and detail == "finished":
        return "finished"
    if status in {"exit", "error"}:
        return "stopped"
    if status in {"running", "claimed", "new", "resuming"}:
        return "running"
    if status == "suspended":
        return "running"
    return status or "running"


def _fetch_all_session_messages(devin_id: str) -> tuple[list[str], list[str]]:
    """Paginate GET .../sessions/{devin_id}/messages (cursor-based, docs v3)."""
    messages: list[str] = []
    devin_messages: list[str] = []
    after: str | None = None

    while True:
        params: dict[str, Any] = {"first": 200}
        if after:
            params["after"] = after

        response = httpx.get(
            _org_resource(f"/sessions/{devin_id}/messages"),
            headers=_auth_headers(),
            params=params,
            timeout=30,
        )
        _raise_for_response(response, "list session messages")
        payload = response.json()

        for item in payload.get("items", []):
            if not isinstance(item, dict) or not item.get("message"):
                continue
            text = str(item["message"])
            messages.append(text)
            if item.get("source") == "devin":
                devin_messages.append(text)

        if not payload.get("has_next_page"):
            break
        after = payload.get("end_cursor")
        if not after:
            break

    return messages, devin_messages


def create_session(prompt: str, session_type: SessionType) -> dict[str, Any]:
    _require_credentials()

    body: dict[str, Any] = {
        "prompt": prompt,
        "title": f"Sentinel {session_type.value}",
        "repos": [f"github.com/{settings.github_repo}"],
    }

    response = httpx.post(
        _org_resource("/sessions"),
        headers=_json_headers(),
        json=body,
        timeout=30,
    )
    _raise_for_response(response, "create session")
    data = response.json()
    session_id = data.get("session_id") or data.get("id")
    return {
        **data,
        "session_id": session_id,
        "url": data.get("url") or f"https://app.devin.ai/sessions/{session_id}",
    }


def get_session(session_id: str) -> dict[str, Any]:
    _require_credentials()
    devin_id = _ensure_devin_id(session_id)

    response = httpx.get(
        _org_resource(f"/sessions/{devin_id}"),
        headers=_auth_headers(),
        timeout=30,
    )
    _raise_for_response(response, "get session")
    data = response.json()
    messages, devin_messages = _fetch_all_session_messages(devin_id)

    return {
        **data,
        "session_id": data.get("session_id") or devin_id,
        "messages": messages,
        "devin_messages": devin_messages,
        "status": _map_v3_status(data),
    }


def extract_messages(session_data: dict[str, Any]) -> list[str]:
    raw_messages = session_data.get("messages") or session_data.get("conversation") or []
    messages: list[str] = []

    for item in raw_messages:
        if isinstance(item, str):
            messages.append(item)
        elif isinstance(item, dict):
            content = item.get("message") or item.get("content") or item.get("text")
            if content:
                messages.append(str(content))

    return messages


def extract_sentinel_messages(session_data: dict[str, Any]) -> list[str]:
    """Messages to scan for AUDIT_DONE / DONE / BLOCKED (Devin output only on v3)."""
    devin_messages = session_data.get("devin_messages")
    if devin_messages is not None:
        return devin_messages
    return extract_messages(session_data)


def parse_done_pr_url(messages: list[str]) -> str | None:
    for message in reversed(messages):
        match = DONE_PATTERN.search(message)
        if match:
            return match.group(1).rstrip(").,")
    return None


def parse_blocked_reason(messages: list[str]) -> str | None:
    for message in reversed(messages):
        match = BLOCKED_PATTERN.search(message)
        if match:
            return match.group(1).strip()
    return None


def parse_audit_done(messages: list[str]) -> list[CveFinding] | None:
    for message in reversed(messages):
        match = AUDIT_DONE_PATTERN.search(message)
        if not match:
            continue
        payload = match.group(1).strip()
        if payload.startswith("```"):
            payload = payload.strip("`").strip()
        data = json.loads(payload)
        return [CveFinding.model_validate(item) for item in data]
    return None
