"""Conservative HTTP execution primitives with explicit target scoping.

Production-safe default supports GET only; disposable workflows may explicitly enable writes. No endpoint is contacted unless the
caller opts in with ``execute=True`` and supplies an exact host allowlist.
Redirects are disabled so a request cannot silently leave the approved host.
"""

from __future__ import annotations

import time
import re
import socket
from ipaddress import ip_address, ip_network
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from achillesapi.core.campaign_ledger import CampaignLedger, CampaignBudgetError

from achillesapi.models.evidence import (
    ExecutionEvidence,
    RequestEvidence,
    ResponseEvidence,
)

_ALLOWED_METHODS = {"GET", "POST", "PATCH", "PUT", "DELETE"}
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
_SENSITIVE_QUERY_NAMES = {"api_key", "apikey", "access_token", "token", "key", "password", "secret"}


class ScopeError(ValueError):
    """Raised when a request falls outside the explicitly authorized scope."""


class RequestBudgetExceeded(RuntimeError):
    """Raised when the configured request budget is exhausted."""


class SafeHTTPClient:
    def __init__(
        self,
        *,
        allowed_hosts: set[str],
        timeout: float = 10.0,
        max_requests: int = 10,
        requests_per_second: float = 1.0,
        max_body_bytes: int = 65_536,
        verify_tls: bool = True,
        allowed_methods: set[str] | None = None,
        allowed_cidrs: set[str] | None = None,
        proxy: str | None = None,
        client_cert: str | tuple[str, str] | None = None,
        ca_bundle: str | None = None,
    ) -> None:
        """In pratica: Inizializza lo stato e le regole di funzionamento del componente.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        if not allowed_hosts:
            raise ValueError("At least one explicitly allowed host is required.")
        if timeout <= 0 or max_requests < 1 or requests_per_second <= 0 or max_body_bytes < 1:
            raise ValueError("Timeout, request budget, rate and body limit must be positive.")
        # Legacy callers remain GET-only. Only the separately approved workflow
        # engine may opt into mutation methods.
        selected = {item.upper() for item in (allowed_methods or {"GET"})}
        if not selected or not selected <= _ALLOWED_METHODS:
            raise ValueError("Allowed HTTP methods must be a nonempty safe subset.")
        self.allowed_methods = selected
        self.allowed_hosts = {host.lower().strip().rstrip(".") for host in allowed_hosts}
        self.timeout = timeout
        self.max_requests = max_requests
        self.interval = 1.0 / requests_per_second
        self.max_body_bytes = max_body_bytes
        self.verify_tls = ca_bundle or verify_tls
        if proxy:
            parsed_proxy = urlsplit(proxy)
            if parsed_proxy.scheme not in {'http', 'https', 'socks5', 'socks5h'} or not parsed_proxy.hostname:
                raise ValueError('Explicit proxy must be http(s) or socks5(h) URL')
            if parsed_proxy.username or parsed_proxy.password:
                raise ValueError('Proxy credentials must not be embedded in configuration URLs')
        self.proxy = proxy
        self.client_cert = client_cert
        # Optional strict IP boundary. With no CIDRs, the legacy exact-host scope
        # remains in effect; nothing is silently changed for existing callers.
        self.allowed_cidrs = tuple(ip_network(value, strict=False) for value in (allowed_cidrs or set()))
        self._requests_made = 0
        # Telemetria locale: contiamo i tentativi, anche se la rete restituisce errore.
        self._responses_received = 0
        self._network_errors = 0
        self._status_classes: dict[str, int] = {}
        self._last_request_at: float | None = None
        # Se eseguito da una suite, tutti i processi condividono un unico budget.
        self._campaign_ledger = CampaignLedger.from_environment()

    @property
    def request_statistics(self) -> dict[str, object]:
        """Conteggi del solo client corrente, non dell'intera campagna.

        Nota: il contatore viene incrementato subito prima della chiamata HTTP.
        Una richiesta fallita in rete rimane un tentativo effettuato.
        """
        return {
            'attempted': self._requests_made,
            'responses_received': self._responses_received,
            'network_errors': self._network_errors,
            'status_classes': dict(self._status_classes),
            'max_requests': self.max_requests,
            'scope': 'this_client_instance_only',
        }

    def _validate_target(self, method: str, url: str) -> None:
        """In pratica: Controlla metodo, protocollo e host prima di qualunque richiesta.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        if method.upper() not in self.allowed_methods:
            raise ScopeError("Only GET requests are enabled by default." if self.allowed_methods == {"GET"}
                             else "HTTP method is not authorized for this client instance.")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ScopeError("Target must be an absolute HTTP(S) URL.")
        if parts.username or parts.password:
            raise ScopeError("Credentials embedded in URLs are not allowed.")
        if parts.fragment or any(segment in (".", "..") for segment in parts.path.split("/")):
            raise ScopeError("Fragments and path-traversal segments are not valid request targets.")
        if "\\" in url or re.search(r"%(?:2e|2f|5c)", url, re.I):
            raise ScopeError("Ambiguous encoded paths are not allowed in scoped requests.")
        if parts.hostname.lower().rstrip(".") not in self.allowed_hosts:
            raise ScopeError(f"Host {parts.hostname!r} is not in the explicit allowlist.")

    def _validate_destination_ips(self, url: str) -> None:
        """Preflight every current DNS answer against explicit approved IP ranges.

        This fails closed if DNS lookup fails or produces ANY out-of-scope IP.
        Note: this does not pin the later HTTP connection's DNS result; to fully
        mitigate rebinding, use a scope-restricting egress proxy/firewall.
        """
        if not self.allowed_cidrs:
            return
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise ScopeError("Missing destination host")
        try:
            candidates = {ip_address(entry[4][0]) for entry in socket.getaddrinfo(
                host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
            )}
        except (OSError, ValueError) as exc:
            raise ScopeError("Destination DNS resolution failed") from exc
        if not candidates or any(not any(candidate in network for network in self.allowed_cidrs)
                                 for candidate in candidates):
            raise ScopeError("Destination DNS includes an IP outside approved CIDR ranges")

    @staticmethod
    def _safe_headers(
        headers: dict[str, str] | httpx.Headers,
        extra_sensitive_names: set[str] | None = None,
    ) -> dict[str, str]:
        """In pratica: Oscura gli header che possono contenere credenziali.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        sensitive = _SENSITIVE_HEADERS | {name.lower() for name in (extra_sensitive_names or set())}
        return {
            key: ("[REDACTED]" if key.lower() in sensitive | {"location", "www-authenticate", "proxy-authenticate"} else value)
            for key, value in headers.items()
        }

    @staticmethod
    def _safe_url(
        url: str,
        extra_sensitive_names: set[str] | None = None,
        extra_params: dict[str, str] | None = None,
    ) -> str:
        """In pratica: Oscura i parametri URL identificati come sensibili.

    Attenzione: Questa funzione non contatta direttamente l'API target.
    """
        parts = urlsplit(url)
        sensitive = _SENSITIVE_QUERY_NAMES | {name.lower() for name in (extra_sensitive_names or set())}
        query_items = parse_qsl(parts.query, keep_blank_values=True)
        query_items.extend((extra_params or {}).items())
        query = [(key, "[REDACTED]" if key.lower() in sensitive else value)
                 for key, value in query_items]
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    def request(
        self,
        method: str,
        url: str,
        *,
        execute: bool = False,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        sensitive_query_names: set[str] | None = None,
        sensitive_header_names: set[str] | None = None,
        json_body: dict[str, object] | None = None,
        form_body: dict[str, str] | None = None,
        xml_body: str | None = None,
        approved_xml_oast_url: str | None = None,
        binary_body: bytes | None = None,
        binary_content_type: str | None = None,
        multipart_files: dict[str, tuple[str, bytes, str]] | None = None,
    ) -> ExecutionEvidence:
        """Create a scoped HTTP request, with GET as the only default method.

        Write methods require an explicitly configured client from the workflow
        engine and must never be used as an automatic fallback. Response bodies
        remain transient evidence and are not automatically written to reports.
        """
        # IN PRATICA: Prepara una richiesta. La esegue solo se il metodo e esplicitamente autorizzato.
        # SICUREZZA: Puo inviare richieste HTTP; verificare scope, identita e autorizzazioni.
        # Payloads are bounded and mutually exclusive. They are accepted only
        # when the calling engine explicitly enables a write method.
        selected_bodies = sum(x is not None for x in (json_body, form_body, xml_body, binary_body, multipart_files))
        if selected_bodies > 1:
            raise ScopeError('Un solo formato body può essere utilizzato per richiesta')
        if form_body is not None and (len(form_body) > 40 or any(
                not isinstance(k, str) or not isinstance(v, str) or len(k) > 100 or len(v) > 4096
                for k, v in form_body.items())):
            raise ScopeError('Form supera i limiti approvati')
        if xml_body is not None:
            if len(xml_body.encode('utf-8')) > 16_384:
                raise ScopeError('XML body troppo esteso')
            if '<!DOCTYPE' in xml_body.upper() or '<!ENTITY' in xml_body.upper():
                if not approved_xml_oast_url:
                    raise ScopeError('XML DTD/entity non consentito: richiede OAST approvato')
                # The only exception is a single bounded outbound HTTP(S) callback.
                # Never send file://, parameter entities, arbitrary DTD or local files.
                from xml.etree import ElementTree
                callback_target = urlsplit(approved_xml_oast_url)
                if (callback_target.scheme not in ('http', 'https') or not callback_target.hostname or
                        callback_target.username or callback_target.password or callback_target.fragment or
                        (callback_target.scheme == 'http' and callback_target.hostname not in ('localhost','127.0.0.1','::1'))):
                    raise ScopeError('OAST XML endpoint non valido')
                # Exact prefix constructed by the RC15 engine (no permissive DTD parsing).
                prefix = re.match(r'\A<!DOCTYPE ([A-Za-z][A-Za-z0-9_-]*) '
                                  r'\[<!ENTITY achilles SYSTEM "([^"<>]+)"\>\]>\s*', xml_body)
                if not prefix or prefix.group(2) != approved_xml_oast_url:
                    raise ScopeError('Only exact Achilles callback DTD can be used')
                remainder = xml_body[prefix.end():]
                if (re.search(r'<!\s*(?:ENTITY|DOCTYPE)', remainder, re.I)
                        or remainder.count('&achilles;') != 1 or '<%' in remainder):
                    raise ScopeError('Unexpected XML entity or document subset')
                try:
                    document = ElementTree.fromstring(remainder.replace('&achilles;', ''))
                except ElementTree.ParseError as exc:
                    raise ScopeError('Invalid XML OAST payload') from exc
                if document.tag != prefix.group(1):
                    raise ScopeError('Unexpected XML OAST root')
        elif approved_xml_oast_url is not None:
            raise ScopeError('OAST approval without XML payload')
        if multipart_files is not None:
            if not multipart_files or len(multipart_files) > 3:
                raise ScopeError('Multipart richiede 1..3 file di prova')
            for field, file_info in multipart_files.items():
                if (not isinstance(field, str) or not isinstance(file_info, tuple)
                        or len(file_info) != 3):
                    raise ScopeError('File multipart non valido')
                filename, content, mime = file_info
                if (not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}\.(?:txt|png|jpg|pdf)', filename)
                        or not isinstance(content, bytes) or len(content) > 16_384
                        or not isinstance(mime, str) or mime not in
                        {'text/plain','image/png','image/jpeg','application/pdf'}):
                    raise ScopeError('Upload fuori dall’allowlist file di prova o sopra 16 KB')
        if binary_body is not None and (len(binary_body) > 16_384 or
                not binary_content_type or len(binary_content_type) > 100):
            raise ScopeError('Upload limitato a 16 KB e richiede Content-Type esplicito')
        self._validate_target(method, url)
        self._validate_destination_ips(url)
        request_headers = dict(headers or {})
        if xml_body is not None:
            request_headers['Content-Type'] = 'application/xml'
        if binary_body is not None:
            request_headers['Content-Type'] = binary_content_type
        request_params = params or {}
        request_cookies = cookies or {}
        request_evidence = RequestEvidence(
            method=method.upper(),
            url=self._safe_url(url, sensitive_query_names, request_params),
            headers=self._safe_headers(request_headers, sensitive_header_names),
        )
        if not execute:
            return ExecutionEvidence(
                request=request_evidence,
                executed=False,
                notes=["Dry run: no network request was sent."],
            )
        if self._requests_made >= self.max_requests:
            raise RequestBudgetExceeded("Maximum request budget reached.")
        now = time.monotonic()
        if self._last_request_at is not None:
            wait = self.interval - (now - self._last_request_at)
            if wait > 0:
                time.sleep(wait)
        self._last_request_at = time.monotonic()
        # Prima della rete prenotiamo una richiesta sul budget globale.
        # Un tentativo fallito resta conteggiato per evitare retry illimitati.
        reservation = None
        if self._campaign_ledger is not None:
            try:
                reservation = self._campaign_ledger.reserve()
            except CampaignBudgetError as exc:
                raise RequestBudgetExceeded(str(exc)) from exc
            if reservation.delay_seconds:
                time.sleep(reservation.delay_seconds)
        self._requests_made += 1
        started = time.monotonic()
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,  # Never leak credentials through an inherited proxy.
                verify=self.verify_tls,
                proxy=self.proxy,
                cert=self.client_cert,
                headers={"User-Agent": "AchillesAPI/0.37.0 (authorized-security-assessment)"},
            ) as client:
                with client.stream(
                    method.upper(), url, headers=request_headers, params=request_params,
                    cookies=request_cookies, json=json_body, data=form_body,
                    content=xml_body.encode('utf-8') if xml_body is not None else binary_body,
                    files=multipart_files
                ) as response:
                    body = bytearray()
                    truncated = False
                    for chunk in response.iter_bytes():
                        remaining = self.max_body_bytes - len(body)
                        if len(chunk) > remaining:
                            body.extend(chunk[:remaining])
                            truncated = True
                            break
                        body.extend(chunk)
                    status_code = response.status_code
                    # Registriamo soltanto la classe (2xx, 4xx...), mai URL o token.
                    label = str(status_code // 100) + 'xx'
                    self._status_classes[label] = self._status_classes.get(label, 0) + 1
                    self._responses_received += 1
                    if reservation is not None:
                        self._campaign_ledger.finish(reservation, status=status_code)
                    safe_headers = self._safe_headers(response.headers)
                    # Never log full Location: it can contain access tokens or IDs.
                    redirect_host = None
                    if 300 <= status_code < 400 and response.headers.get('location'):
                        redirect_host = urlsplit(response.headers['location']).hostname
                    encoding = response.encoding or "utf-8"
            elapsed_ms = (time.monotonic() - started) * 1000
            return ExecutionEvidence(
                request=request_evidence,
                response=ResponseEvidence(
                    status_code=status_code,
                    headers=safe_headers,
                    body_preview=bytes(body).decode(encoding, errors="replace"),
                    body_truncated=truncated,
                    redirect_host=redirect_host,
                    elapsed_ms=round(elapsed_ms, 2),
                ),
                executed=True,
                notes=["Redirects are disabled; only the allowlisted host was contacted."],
            )
        except httpx.HTTPError as exc:
            if reservation is not None:
                self._campaign_ledger.finish(reservation, status=None)
            self._network_errors += 1
            return ExecutionEvidence(
                request=request_evidence,
                error=type(exc).__name__,
                executed=True,
                notes=["Request was attempted; inspect the error before retrying."],
            )
