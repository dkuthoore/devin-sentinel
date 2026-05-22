import logging

import httpx

from orchestrator.config import settings

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
REQUIRED_LABELS = ["security", "cve", "automated", "dependencies"]


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _repo_url(path: str) -> str:
    return f"{GITHUB_API}/repos/{settings.github_repo}/{path.lstrip('/')}"


def _require_token() -> None:
    if not settings.github_token:
        raise RuntimeError("GITHUB_TOKEN is required")


def ensure_labels() -> None:
    """Create labels if missing. Failures are logged, not fatal to the demo."""
    _require_token()
    colors = {
        "security": "B60205",
        "cve": "D93F0B",
        "automated": "5319E7",
        "dependencies": "0366D6",
    }
    with httpx.Client(timeout=30) as client:
        for label in REQUIRED_LABELS:
            response = client.post(
                _repo_url("labels"),
                headers=_headers(),
                json={"name": label, "color": colors[label], "description": "Created by Sentinel"},
            )
            if response.status_code not in {201, 422}:
                logger.warning("Could not create GitHub label %s: %s", label, response.text)


def create_issue(
    cve_id: str,
    package: str,
    current_version: str,
    fix_version: str,
    description: str,
) -> dict:
    body = f"""## Vulnerability Summary
- **CVE ID**: `{cve_id}`
- **Package**: `{package}`
- **Current version**: `{current_version}`
- **Fixed version**: `{fix_version}`
- **Description**: {description[:800]}

## File to Modify
`requirements/base.txt`

## Acceptance Criteria
- [ ] `{package}` upgraded to `>={fix_version}` in `requirements/base.txt`
- [ ] Relevant tests pass after the upgrade
- [ ] Pull request opened referencing this issue

---
Created automatically by Sentinel.
"""
    title = f"[SECURITY] {cve_id}: {package} {current_version} -> {fix_version}"

    ensure_labels()
    response = httpx.post(
        _repo_url("issues"),
        headers=_headers(),
        json={"title": title, "body": body, "labels": REQUIRED_LABELS},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def get_open_issues_with_label(label: str = "cve") -> list[dict]:
    _require_token()
    response = httpx.get(
        _repo_url("issues"),
        headers=_headers(),
        params={"labels": label, "state": "open", "per_page": 100},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def find_issue_by_cve(cve_id: str) -> dict | None:
    for issue in get_open_issues_with_label("cve"):
        if cve_id in issue.get("title", "") or cve_id in (issue.get("body") or ""):
            return issue
    return None


def get_pull(pr_number: int) -> dict | None:
    _require_token()
    response = httpx.get(
        _repo_url(f"pulls/{pr_number}"),
        headers=_headers(),
        timeout=30,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def find_pr_for_issue(issue_number: int) -> dict | None:
    needle = f"#{issue_number}"
    close_needle = f"closes #{issue_number}"

    _require_token()
    response = httpx.get(
        _repo_url("pulls"),
        headers=_headers(),
        params={"state": "all", "per_page": 100},
        timeout=30,
    )
    response.raise_for_status()
    for pr in response.json():
        body = pr.get("body", "") or ""
        if needle in body or close_needle in body.lower():
            return pr
    return None


def _sha_from_commits_response(data: list | dict) -> str | None:
    """Parse SHA from list-commits JSON or a single-commit object."""
    if isinstance(data, list):
        if not data:
            return None
        first = data[0]
        return first.get("sha") if isinstance(first, dict) else None
    if isinstance(data, dict):
        return data.get("sha")
    return None


def get_branch_head_sha(branch: str | None = None) -> str | None:
    """Return the current commit SHA at the tip of the given branch."""
    ref = branch or settings.github_default_branch
    _require_token()
    response = httpx.get(
        _repo_url("commits"),
        headers=_headers(),
        params={"sha": ref, "per_page": 1},
        timeout=30,
    )
    if response.status_code == 404:
        logger.warning("GitHub branch not found: %s", ref)
        return None
    response.raise_for_status()
    return _sha_from_commits_response(response.json())
