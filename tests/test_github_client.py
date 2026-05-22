from orchestrator.github_client import _sha_from_commits_response


def test_sha_from_commits_list():
    data = [{"sha": "abc123", "commit": {}}]
    assert _sha_from_commits_response(data) == "abc123"


def test_sha_from_single_commit_object():
    data = {"sha": "def456", "commit": {}}
    assert _sha_from_commits_response(data) == "def456"


def test_sha_from_empty_list():
    assert _sha_from_commits_response([]) is None
