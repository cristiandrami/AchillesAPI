"""Bilancio HTTP condiviso: un unico limite anche con più subprocessi.

Appunti per chi legge:
- Ogni processo apre lo stesso piccolo database SQLite.
- La transazione IMMEDIATE prenota una richiesta in modo atomico.
- Un timeout di rete NON restituisce il credito: il tentativo è già avvenuto.
- Il database contiene solo contatori e codici HTTP, mai URL o credenziali.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path


class CampaignBudgetError(RuntimeError):
    """Il budget, il tempo o la configurazione della campagna impediscono l'HTTP."""


@dataclass(frozen=True)
class Reservation:
    """Ticket non segreto usato per aggiornare il contatore a fine richiesta."""

    identifier: str
    delay_seconds: float


class CampaignLedger:
    """Contatore persistente e condiviso tra tutti i processi della stessa suite."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise CampaignBudgetError('Registro HTTP della campagna non disponibile')

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(str(path), timeout=15, isolation_level=None)
        connection.execute('PRAGMA busy_timeout=15000')
        return connection

    @classmethod
    def create(cls, path: str | Path, *, limit: int, rate: float,
               runtime_seconds: int) -> 'CampaignLedger':
        """Crea un nuovo registro, senza inviare traffico HTTP."""
        if not 1 <= limit <= 100000 or not 0.05 <= rate <= 100 or not 1 <= runtime_seconds <= 86400:
            raise ValueError('Limiti HTTP e durata della campagna non validi')
        destination = Path(path)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.exists():
            raise CampaignBudgetError('Il registro della campagna esiste già')
        # Il file non deve essere leggibile da altri utenti del sistema.
        descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        try:
            with closing(cls._connect(destination)) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), '
                           'request_limit INTEGER NOT NULL, rate REAL NOT NULL, '
                           'deadline REAL NOT NULL, next_slot REAL NOT NULL DEFAULT 0, '
                           'attempted INTEGER NOT NULL DEFAULT 0, '
                           'responded INTEGER NOT NULL DEFAULT 0, errors INTEGER NOT NULL DEFAULT 0)')
                db.execute('CREATE TABLE attempts (ticket TEXT PRIMARY KEY, '
                           'created REAL NOT NULL, status INTEGER, outcome TEXT NOT NULL)')
                db.execute('INSERT INTO state(id,request_limit,rate,deadline) VALUES (1,?,?,?)',
                           (limit, rate, time.time() + runtime_seconds))
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
        return cls(destination)

    @classmethod
    def from_environment(cls) -> 'CampaignLedger | None':
        """Se la suite ha impostato il percorso, attiviamo i limiti globali."""
        name = os.environ.get('ACHILLES_CAMPAIGN_LEDGER')
        return cls(name) if name else None

    def extend_limit(self, new_limit: int, *, maximum: int = 600) -> dict[str, object]:
        """Explicit operator-approved retry increase; preserve all past attempts."""
        if not 1 <= new_limit <= maximum:
            raise CampaignBudgetError('Nuovo budget oltre il limite della campagna')
        with closing(self._connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            state=db.execute('SELECT request_limit,attempted FROM state WHERE id=1').fetchone()
            if state is None:
                db.rollback()
                raise CampaignBudgetError('Registro HTTP danneggiato')
            old, attempted=state
            if new_limit < old or new_limit < attempted:
                db.rollback()
                raise CampaignBudgetError('Non puoi ridurre un budget già consumato')
            db.execute('UPDATE state SET request_limit=? WHERE id=1',(new_limit,))
            db.commit()
        return self.snapshot()

    def reserve(self) -> Reservation:
        """Prenota UN tentativo e il relativo slot di rate limiting.

        In pratica: BEGIN IMMEDIATE impedisce a due processi di usare l'ultimo
        credito insieme. Il sonno avviene DOPO il commit, mai con lock aperto.
        """
        now = time.time()
        ticket = uuid.uuid4().hex
        with closing(self._connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT request_limit,rate,deadline,next_slot,attempted '
                             'FROM state WHERE id=1').fetchone()
            if row is None:
                raise CampaignBudgetError('Registro HTTP danneggiato')
            limit, rate, deadline, next_slot, count = row
            slot = max(now, next_slot)
            if count >= limit:
                raise CampaignBudgetError('Budget HTTP globale esaurito')
            if slot >= deadline:
                raise CampaignBudgetError('Durata massima della campagna superata')
            db.execute('UPDATE state SET attempted=attempted+1, next_slot=? WHERE id=1',
                       (slot + 1.0/rate,))
            db.execute('INSERT INTO attempts(ticket,created,outcome) VALUES(?,?,?)',
                       (ticket, now, 'reserved'))
            db.commit()
        delay = max(0.0, slot - time.time())
        return Reservation(identifier=ticket, delay_seconds=delay)

    def finish(self, ticket: Reservation, *, status: int | None) -> None:
        """Registra soltanto lo stato HTTP; se manca una risposta conta un errore."""
        valid = status if isinstance(status, int) and 100 <= status <= 599 else None
        with closing(self._connect(self.path)) as db:
            db.execute('BEGIN IMMEDIATE')
            result = db.execute('UPDATE attempts SET status=?, outcome=? '
                                'WHERE ticket=? AND outcome=?',
                                (valid, 'response' if valid is not None else 'network_error',
                                 ticket.identifier, 'reserved'))
            if result.rowcount:
                db.execute('UPDATE state SET responded=responded+?, errors=errors+? WHERE id=1',
                           (int(valid is not None), int(valid is None)))
            db.commit()

    def snapshot(self) -> dict[str, object]:
        """Restituisce statistiche aggregate, mai contenuti di request/response."""
        with closing(self._connect(self.path)) as db:
            state = db.execute('SELECT request_limit, rate, deadline, attempted, responded, errors '
                               'FROM state WHERE id=1').fetchone()
            if not state:
                raise CampaignBudgetError('Registro HTTP danneggiato')
            status = db.execute('SELECT status/100, COUNT(*) FROM attempts '
                                'WHERE status IS NOT NULL GROUP BY status/100').fetchall()
        limit, rate, deadline, attempted, responded, errors = state
        return {'scope': 'campaign_all_processes', 'limit': limit, 'rate_per_second': rate,
                'deadline_utc': deadline, 'attempted': attempted, 'responses_received': responded,
                'network_errors': errors, 'pending': attempted-responded-errors,
                'remaining': limit-attempted,
                'status_classes': {str(int(k))+'xx': v for k, v in status}}
