import pytest

from orchestrator.config import ConfigurationError, Settings, validate_required_settings


def test_validate_required_settings_passes_with_all_required_values():
    validate_required_settings(
        Settings.model_construct(
            devin_api_key="key",
            devin_org_id="org-test",
            github_token="ghp_test",
            github_repo="owner/repo",
        )
    )


def test_validate_required_settings_lists_all_missing():
    with pytest.raises(ConfigurationError) as exc_info:
        validate_required_settings(
            Settings.model_construct(
                devin_api_key="",
                devin_org_id="",
                github_token="",
                github_repo="yourusername/superset",
            )
        )

    message = str(exc_info.value)
    assert message.count("is required but missing") == 4
    assert "DEVIN_API_KEY" in message
    assert "DEVIN_ORG_ID" in message
    assert "GITHUB_TOKEN" in message
    assert "GITHUB_REPO" in message


def test_validate_required_settings_rejects_placeholder_repo():
    with pytest.raises(ConfigurationError) as exc_info:
        validate_required_settings(
            Settings.model_construct(
                devin_api_key="key",
                devin_org_id="org-test",
                github_token="ghp_test",
                github_repo="yourusername/superset",
            )
        )

    message = str(exc_info.value)
    assert "GITHUB_REPO is required but missing" in message
    assert "DEVIN_API_KEY" not in message
