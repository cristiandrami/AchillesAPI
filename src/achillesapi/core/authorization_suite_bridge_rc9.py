"""Strict, read-only adapter from a saved access matrix to suite authorization tasks.

A policy file is an operator assertion, not an inferred permission. Never
invent an ID, identity or expected outcome. No network traffic occurs here.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from achillesapi.core.access_matrix_rc4 import read_rules, preflight_rules
from achillesapi.core.auth import load_authentication_manager


def validated_suite_rules(spec: str | Path, auth: str | Path, rules_path: str | Path) -> list[dict[str, Any]]:
    manager = load_authentication_manager(auth)
    return preflight_rules(spec, read_rules(rules_path), profile_names=set(manager.names))


def probe_from_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """One *explicit* rule drives access-probe; access-matrix covers all rules."""
    return {
        'operation': rule['operation'],
        'profiles': [rule['owner'], rule['other']],
        'expected_owner': rule['expected_owner'],
        'expected_other': rule['expected_other'],
        'path_values': [f'{name}={value}' for name, value in rule['path_values'].items()],
        'matrix_rule_id': rule['id'],
    }
