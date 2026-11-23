"""RC4 — Avvia e termina in modo controllato i comandi figli della dashboard.

Appunti pratici:
- Usiamo un array di argomenti, MAI una stringa passata a una shell.
- Il subprocesso parte in un proprio gruppo: sul timeout terminiamo
  anche gli eventuali figli generati dal comando CLI.
- Leggiamo solo la coda degli errori: non salviamo log illimitati.
- Un timeout durante un workflow non dimostra che il cleanup sia riuscito.
"""
from __future__ import annotations

import os
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class ProcessOutcome:
    """Solo le informazioni necessarie alla dashboard (senza stdout sensibile)."""
    returncode: int
    stderr: str


def _terminate_tree(process: subprocess.Popen, *, grace: float = 2.0) -> None:
    """Termina l'intero gruppo del processo senza lanciare comandi shell."""
    if process.poll() is not None:
        return
    if os.name == 'nt':
        # /T chiude anche i processi figli. PID proviene dal processo appena creato.
        subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False, timeout=8)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=8)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=8)


def run_cli_bounded(command: Sequence[str], *, cwd: str | Path,
                    env: Mapping[str, str], timeout: float = 480) -> ProcessOutcome:
    """Esegue una CLI e arresta l'albero dei subprocessi quando scade il tempo.

    stdout non viene mostrato: i report strutturati sono salvati da ogni CLI.
    stderr viene troncato a 16 KiB; la dashboard oscura anche i token inline.
    """
    if not command or any(not isinstance(item, str) or '\x00' in item for item in command):
        raise ValueError('Comando CLI non valido')
    if not 0 < timeout <= 3600:
        raise ValueError('Timeout fuori dai limiti previsti')
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
    with tempfile.TemporaryFile(mode='w+b') as error_stream:
        proc = subprocess.Popen(list(command), cwd=str(cwd), env=dict(env),
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=error_stream, shell=False,
                                start_new_session=(os.name != 'nt'),
                                creationflags=flags)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            _terminate_tree(proc)
            raise subprocess.TimeoutExpired(command, timeout) from exc
        # Manteniamo solo gli ultimi 16 KiB degli errori, non i body HTTP.
        error_stream.seek(0, os.SEEK_END)
        end = error_stream.tell()
        error_stream.seek(max(0, end - 16384))
        stderr = error_stream.read().decode('utf-8', errors='replace')
        return ProcessOutcome(proc.returncode, stderr)
