"""SQLite-backed local history for dashboard jobs and sanitized suite contexts.

Only metadata and nonsecret configuration pointers are written here; full
assessment artifacts remain in reports/. Credentials in uploaded auth files are
separate and already limited to owner read/write. This is NOT durable queueing:
interrupted subprocesses never resume automatically after restarting the server.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

_ID = re.compile(r'^[a-f0-9]{32}$')


class CampaignStore:
    def __init__(self, root: Path) -> None:
        self.path = root / 'campaigns.sqlite3'
        self._lock = threading.RLock()
        with self._connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS suites (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _connection(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path), timeout=10)

    def save_job(self, job: dict[str, Any]) -> None:
        key = job.get('id')
        if not isinstance(key, str) or not _ID.fullmatch(key):
            return
        # Explicitly remove fields that could accidentally be inserted by a caller.
        sanitized = {k: v for k, v in job.items() if k not in {
            'secrets', 'password', 'token', 'headers', 'body', 'command', 'env', 'credentials'}}
        with self._lock, self._connection() as db:
            db.execute('INSERT OR REPLACE INTO jobs(id,body) VALUES (?,?)',
                       (key, json.dumps(sanitized, ensure_ascii=False)))

    def save_jobs(self, jobs: dict[str, dict[str, Any]]) -> None:
        for job in list(jobs.values()):
            self.save_job(job)

    def load_jobs(self) -> dict[str, dict[str, Any]]:
        with self._lock, self._connection() as db:
            records = db.execute('SELECT id,body FROM jobs').fetchall()
        jobs = {}
        for key, payload in records:
            try:
                job = json.loads(payload)
                if not _ID.fullmatch(key) or not isinstance(job, dict):
                    continue
                if job.get('status') in ('running', 'orchestrating'):
                    job['status'] = 'failed'
                    job['error'] = 'Esecuzione interrotta dal riavvio della dashboard: non ripresa automaticamente.'
                    job['current_step'] = None
                    self.save_job(job)
                jobs[key] = job
            except (ValueError, TypeError):
                continue
        return jobs

    def save_suite_context(self, key: str, context: Any) -> None:
        if not _ID.fullmatch(key):
            return
        item = context.model_dump(mode='json') if hasattr(context, 'model_dump') else dict(context)
        if isinstance(item.get('config'), dict):
            item['config'].pop('secrets', None)
            item['config'].pop('acknowledgment', None)  # require renewed consent
            item['config'].pop('approve_writes', None)
        with self._lock, self._connection() as db:
            db.execute('INSERT OR REPLACE INTO suites(id,body) VALUES (?,?)',
                       (key, json.dumps(item, ensure_ascii=False)))

    def load_suite_contexts(self) -> dict[str, dict[str, Any]]:
        with self._lock, self._connection() as db:
            rows = db.execute('SELECT id,body FROM suites').fetchall()
        recovered = {}
        for key, content in rows:
            try:
                if _ID.fullmatch(key):
                    item = json.loads(content)
                    if isinstance(item, dict):
                        recovered[key] = item
            except (TypeError, ValueError):
                pass
        return recovered


class PersistentJobRegistry(dict):
    """Persist new jobs immediately; completion mutations need save_jobs()."""
    def __init__(self, store: CampaignStore):
        self.store = store
        super().__init__(store.load_jobs())

    def __setitem__(self, key: str, value: dict[str, Any]) -> None:
        super().__setitem__(key, value)
        self.store.save_job(value)
