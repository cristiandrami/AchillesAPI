from __future__ import annotations

import base64
from pathlib import Path

import pytest

from achillesapi.core.auth import AuthenticationConfigError, AuthenticationManager


def write_config(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def test_bearer_profile_resolves_secret_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = write_config(tmp_path / "auth.yaml", "profiles:\n  - name: alice\n    type: bearer\n    token_env: TEST_ALICE_TOKEN\n")
    monkeypatch.setenv("TEST_ALICE_TOKEN", "secret-token")
    material = AuthenticationManager.from_file(config).resolve("alice")
    assert material.headers == {"Authorization": "Bearer secret-token"}
    assert "secret-token" not in repr(material)


def test_basic_profile_encodes_username_and_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = write_config(tmp_path / "auth.yaml", "profiles:\n  - name: basic\n    type: basic\n    username_env: TEST_USER\n    password_env: TEST_PASS\n")
    monkeypatch.setenv("TEST_USER", "alice")
    monkeypatch.setenv("TEST_PASS", "p@ss")
    material = AuthenticationManager.from_file(config).resolve("basic")
    expected = base64.b64encode(b"alice:p@ss").decode()
    assert material.headers["Authorization"] == f"Basic {expected}"


@pytest.mark.parametrize(("location", "expected"), [("header", "headers"), ("query", "params"), ("cookie", "cookies")])
def test_api_key_supports_header_query_and_cookie(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str, expected: str
) -> None:
    config = write_config(tmp_path / "auth.yaml", f"profiles:\n  - name: key\n    type: api_key\n    location: {location}\n    parameter_name: X-Key\n    value_env: TEST_API_KEY\n")
    monkeypatch.setenv("TEST_API_KEY", "key-secret")
    material = AuthenticationManager.from_file(config).resolve("key")
    assert getattr(material, expected)["X-Key"] == "key-secret"


def test_missing_secret_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = write_config(tmp_path / "auth.yaml", "profiles:\n  - name: alice\n    type: bearer\n    token_env: ABSENT_TOKEN\n")
    monkeypatch.delenv("ABSENT_TOKEN", raising=False)
    with pytest.raises(AuthenticationConfigError, match="not set"):
        AuthenticationManager.from_file(config).resolve("alice")


def test_duplicate_names_are_rejected(tmp_path: Path) -> None:
    config = write_config(tmp_path / "auth.yaml", "profiles:\n  - name: same\n    type: bearer\n    token_env: A\n  - name: same\n    type: bearer\n    token_env: B\n")
    with pytest.raises(AuthenticationConfigError, match="unique"):
        AuthenticationManager.from_file(config)


def test_describe_never_reads_or_exposes_secret(tmp_path: Path) -> None:
    config = write_config(tmp_path / "auth.yaml", "profiles:\n  - name: alice\n    type: bearer\n    token_env: TEST_TOKEN\n")
    manager = AuthenticationManager.from_file(config)
    assert manager.describe() == [{"name": "alice", "type": "bearer", "location": "header", "environment_variables": ["TEST_TOKEN"]}]
