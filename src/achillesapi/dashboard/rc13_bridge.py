"""Dashboard adapter for the *existing* RC13 CLI (no parallel scanner implementation).

All inputs are opaque upload IDs resolved by the control plane. The adapter
only builds an allowlisted, shell-free command. No HTTP is performed here.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from achillesapi.core.openapi import load_openapi
from achillesapi.core.pipeline_rc13 import create_plan

_PROFILE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_MODEL = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,119}$')
_PATH = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}=[^\r\n]{1,256}$')


def rc13_paths(config, file_id, uploaded_config):
    """Resolve only server-owned files, never paths supplied by a browser."""
    spec = file_id(config.specification_id, '.yaml')
    auth = file_id(config.auth_config_id, '.auth.yaml') if config.auth_config_id else None
    rules = uploaded_config(config.access_rules_id) if config.access_rules_id else None
    workflow = (uploaded_config(config.config_id)
                if config.config_id and config.config_usage in {'workflow', 'multi-resource'}
                else None)
    if rules and not auth:
        raise ValueError('La matrice di accesso richiede auth.yaml.')
    return spec, auth, rules, workflow


def rc13_plan(config, file_id, uploaded_config):
    spec, auth, rules, workflow = rc13_paths(config, file_id, uploaded_config)
    return create_plan(spec, auth_config=auth, rules_path=rules, workflow_config=workflow)


def rc13_command(config, file_id, uploaded_config, *, active: bool, writes: bool,
                 body_probes: bool, ai: bool, max_requests: int, output: Path,
                 agent_followups: bool = False, agent_rounds: int = 2, agent_budget: int = 24,
                 body_probe_fields: list[str] | None = None,
                 rc15_callback_base: str | None = None, rc15_callback_observer: str | None = None,
                 rc15_fixture_file: str | None = None, rc15_fixture_marker: str | None = None) -> list[str]:
    if not 1 <= max_requests <= 1000:
        raise ValueError('Budget RC13 fuori limite (1–1000).')
    spec, auth, rules, workflow = rc13_paths(config, file_id, uploaded_config)
    if not _MODEL.fullmatch(config.model):
        raise ValueError('Nome modello Ollama non valido.')
    if len(config.profiles) > 6 or any(not _PROFILE.fullmatch(p) for p in config.profiles):
        raise ValueError('Profili auth.yaml non validi.')
    if len(config.path_values) > 15 or any(not _PATH.fullmatch(p) for p in config.path_values):
        raise ValueError('Valori path: usa NAME=VALUE su righe separate.')
    if writes and (not active or not workflow or not auth):
        raise ValueError('Scritture RC13: richiedono HTTP attivo, auth.yaml e manifest workflow.')
    if body_probes and not writes:
        raise ValueError('Sonde JSON: prima autorizza esplicitamente le scritture e il cleanup.')
    if agent_followups and (not active or not ai):
        raise ValueError('RC17 agent requires active approved HTTP and local AI.')
    if agent_followups and (not 1 <= agent_rounds <= 3 or not 2 <= agent_budget <= 60):
        raise ValueError('RC17 agent rounds or budget invalid.')

    # Active runs that are not write-approved MUST NOT pass a disposable
    # workflow to execute_pipeline: that engine intentionally rejects it.
    if active and not writes:
        workflow = None
    command = [sys.executable, '-m', 'achillesapi.cli', 'rc13-assess', str(spec),
               '--output', str(output), '--max-requests', str(max_requests),
               '--rate', str(config.rate), '--model', config.model]
    if active:
        command.extend(['--base-url', config.base_url, '--allow-host', config.allow_host, '--execute'])
        if config.allow_insecure_http:
            command.append('--allow-insecure-http')
    if auth:
        command.extend(['--auth-config', str(auth)])
    if config.profiles:
        command.extend(['--profile', config.profiles[0]])
    if rules:
        command.extend(['--rules', str(rules)])
    if workflow:
        command.extend(['--workflow-config', str(workflow)])
    if writes:
        command.append('--approve-writes')
    if body_probes:
        command.extend(['--body-probes', '--approve-body-probes'])
    for field in body_probe_fields or []:
        command.extend(['--body-probe-field', field])
    for label, item in (('--rc15-callback-base', rc15_callback_base),
                        ('--rc15-callback-observer', rc15_callback_observer),
                        ('--rc15-fixture-file', rc15_fixture_file),
                        ('--rc15-fixture-marker', rc15_fixture_marker)):
        if item:
            command.extend([label, item])
    if ai:
        command.append('--ai')
    if agent_followups:
        command.extend(['--agent-followups', '--agent-rounds', str(agent_rounds),
                        '--agent-budget', str(agent_budget)])
    for entry in config.path_values:
        command.extend(['--path-value', entry])
    return command
