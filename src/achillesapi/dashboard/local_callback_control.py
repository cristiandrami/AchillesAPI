"""Dashboard-owned loopback SSRF/XXE callback collector.

All operations are local and opt-in. No user-provided host, URL or command is
executed. A collector started externally is detected, but cannot be stopped by
this dashboard instance.
"""
from __future__ import annotations

import threading
import urllib.error
import urllib.request

from achillesapi.core.rc15_callback import RC15Collector


class LocalCallbackControl:
    def __init__(self, port: int = 8788):
        if not 1024 <= port <= 65535:
            raise ValueError('Porta callback non consentita')
        self.port = port
        self._lock = threading.RLock()
        self._collector: RC15Collector | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f'http://127.0.0.1:{self.port}'

    def _probe(self) -> bool:
        """Identify the collector's protocol on the *fixed* loopback port."""
        req = urllib.request.Request(self.url + '/observed/' + '0' * 32)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=0.35) as response:
                return response.status == 200 and response.read(16) in (b'false', b'true')
        except (urllib.error.URLError, OSError, TimeoutError, ValueError):
            return False

    def status(self) -> dict[str, object]:
        with self._lock:
            owned = bool(self._thread and self._thread.is_alive())
            reachable = self._probe()
            return {'running': reachable, 'managed_here': owned, 'url': self.url,
                    'callback_base': self.url, 'callback_observer': self.url,
                    'message': ('Collector locale attivo' if reachable else
                                'Collector non raggiungibile su localhost')}

    def start(self) -> dict[str, object]:
        with self._lock:
            if self._probe():
                return self.status()
            if self._thread and self._thread.is_alive():
                return self.status()
            try:
                collector = RC15Collector(port=self.port)
            except OSError as exc:
                raise RuntimeError('Porta callback occupata. Chiudi il processo sulla porta '
                                   f'{self.port}, oppure avvia il collector dal terminale.') from exc
            self._collector = collector
            self._thread = threading.Thread(target=collector.serve, daemon=True,
                                            name='achilles-local-callback')
            self._thread.start()
            return self.status()

    def stop(self) -> dict[str, object]:
        with self._lock:
            if not self._collector or not self._thread or not self._thread.is_alive():
                raise RuntimeError('La dashboard può arrestare soltanto il collector avviato da questa sessione.')
            self._collector.close()
            self._thread.join(timeout=1.5)
            self._collector = None
            self._thread = None
            return self.status()
