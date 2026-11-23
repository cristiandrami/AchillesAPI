"""Bounded, offline-first OAuth2/OIDC and JOSE verification for AchillesAPI RC18.

No discovery request is issued unless the caller explicitly supplies --execute and
an approved hostname. JWTs and identity claims are never persisted in reports.
This is an audit of API configuration, not an authorization vulnerability proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

ALLOWED_ALGORITHMS = frozenset({'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'ES256', 'ES384'})
MAX_RESPONSE = 128 * 1024


class OIDCSafetyError(ValueError):
    """Unsafe input, missing trust context or failed explicitly approved discovery."""


def _url_status(url: str, *, require_https: bool = True) -> str | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in ({'https'} if require_https else {'https', 'http'}):
            return 'invalid_or_insecure_scheme'
        if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            return 'invalid_endpoint_url'
        return None
    except (ValueError, TypeError):
        return 'invalid_endpoint_url'


def fetch_approved_json(url: str, *, allowed_hosts: set[str],
                        allow_insecure_http: bool = False, timeout: float = 6.0) -> dict[str, Any]:
    """Never follow redirects or use system proxy; reject off-scope URL before I/O."""
    if _url_status(url, require_https=not allow_insecure_http):
        raise OIDCSafetyError('OIDC endpoint invalid or HTTPS requirement not satisfied')
    parsed = urlsplit(url)
    approved = {host.strip().lower().rstrip('.') for host in allowed_hosts}
    if parsed.hostname is None or parsed.hostname.lower().rstrip('.') not in approved:
        raise OIDCSafetyError('OIDC endpoint not present in explicit host allowlist')
    if parsed.query:
        raise OIDCSafetyError('OIDC discovery with query parameters is disabled')
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False, verify=True) as client:
            with client.stream('GET', url, headers={'Accept': 'application/json'}) as response:
                if response.status_code != 200:
                    raise OIDCSafetyError(f'OIDC discovery returned HTTP {response.status_code}')
                raw = bytearray()
                for chunk in response.iter_bytes():
                    raw.extend(chunk)
                    if len(raw) > MAX_RESPONSE:
                        raise OIDCSafetyError('OIDC discovery response too large')
        value = json.loads(bytes(raw))
    except (httpx.HTTPError, UnicodeError, json.JSONDecodeError) as exc:
        raise OIDCSafetyError('OIDC discovery request failed or did not return JSON') from exc
    if not isinstance(value, dict):
        raise OIDCSafetyError('OIDC response must be an object')
    return value


def _finding(code: str, severity: str, location: str, detail: str) -> dict[str, str]:
    return {'code': code, 'severity': severity, 'location': location, 'detail': detail,
            'evidence_level': 'configuration_observation'}


def audit_openapi_oauth(spec: dict[str, Any]) -> dict[str, Any]:
    """Inspect declared OAuth2/OIDC schemes and scopes without declaring exploits."""
    schemes = (spec.get('components') or {}).get('securitySchemes') or {}
    findings: list[dict[str, str]] = []
    inventory: list[dict[str, Any]] = []
    for name, scheme in schemes.items() if isinstance(schemes, dict) else []:
        if not isinstance(scheme, dict) or scheme.get('type') not in {'oauth2', 'openIdConnect'}:
            continue
        kind = scheme['type']
        flows = scheme.get('flows') or {}
        known_scopes: set[str] = set()
        flow_names: list[str] = []
        if kind == 'openIdConnect':
            url = scheme.get('openIdConnectUrl') or ''
            if _url_status(url):
                findings.append(_finding('OIDC_DISCOVERY_URL', 'medium', name,
                                         'OIDC discovery URL must be valid HTTPS'))
        if kind == 'oauth2' and isinstance(flows, dict):
            for flow, props in flows.items():
                if not isinstance(props, dict):
                    continue
                flow_names.append(flow)
                declared = props.get('scopes') or {}
                if isinstance(declared, dict):
                    known_scopes.update(str(item) for item in declared)
                for field in ('authorizationUrl', 'tokenUrl', 'refreshUrl'):
                    url = props.get(field)
                    if url and _url_status(url):
                        findings.append(_finding('OAUTH_ENDPOINT_HTTP', 'medium', f'{name}.{flow}.{field}',
                                                 'OAuth endpoint should use HTTPS'))
                if flow == 'implicit':
                    findings.append(_finding('OAUTH_IMPLICIT_FLOW', 'medium', name,
                                             'Legacy implicit flow is declared; prefer authorization code with PKCE'))
                if flow == 'password':
                    findings.append(_finding('OAUTH_PASSWORD_FLOW', 'medium', name,
                                             'Legacy resource-owner-password flow is declared'))
        inventory.append({'name': name, 'type': kind,
                          'flows': sorted(flow_names), 'declared_scopes': sorted(known_scopes)})
        for path, operations in (spec.get('paths') or {}).items():
            if not isinstance(operations, dict):
                continue
            for method, operation in operations.items():
                if method.lower() not in {'get','post','patch','put','delete','options','head','trace'} or not isinstance(operation, dict):
                    continue
                requirements = operation.get('security', spec.get('security', []))
                for requirement in requirements if isinstance(requirements, list) else []:
                    if not isinstance(requirement, dict) or name not in requirement:
                        continue
                    for scope in requirement.get(name, []):
                        if kind == 'oauth2' and scope not in known_scopes:
                            findings.append(_finding('OAUTH_UNDECLARED_SCOPE', 'low', f'{method.upper()} {path}',
                                                     f'Scope {scope!r} is required but not declared in the OAuth flow'))
    return {'schemes': inventory, 'findings': findings,
            'result_type': 'passive_openapi_security_review'}


def audit_metadata(metadata: Mapping[str, Any], *, expected_issuer: str | None = None) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    issuer = metadata.get('issuer')
    if not isinstance(issuer, str) or _url_status(issuer):
        issues.append(_finding('OIDC_ISSUER', 'high', 'issuer', 'Issuer is missing or not a valid HTTPS URL'))
    if expected_issuer and issuer != expected_issuer:
        issues.append(_finding('OIDC_ISSUER_MISMATCH', 'high', 'issuer',
                               'Discovery issuer differs from configured expected issuer'))
    for key in ('jwks_uri', 'authorization_endpoint', 'token_endpoint'):
        value = metadata.get(key)
        if value is not None and (not isinstance(value, str) or _url_status(value)):
            issues.append(_finding('OIDC_INSECURE_ENDPOINT', 'medium', key,
                                   'Discovery endpoint must use HTTPS'))
    methods = metadata.get('code_challenge_methods_supported')
    if not isinstance(methods, list) or 'S256' not in methods:
        issues.append(_finding('OIDC_PKCE_S256_UNDECLARED', 'low', 'code_challenge_methods_supported',
                               'PKCE S256 support not declared; confirm with provider'))
    if 'implicit' in (metadata.get('grant_types_supported') or []):
        issues.append(_finding('OIDC_IMPLICIT_SUPPORTED', 'low', 'grant_types_supported',
                               'Legacy implicit grant is advertised'))
    if 'none' in (metadata.get('id_token_signing_alg_values_supported') or []):
        issues.append(_finding('OIDC_UNSIGNED_ID_TOKEN', 'high', 'id_token_signing_alg_values_supported',
                               'Provider advertises unsigned ID tokens'))
    return {'issuer_matches': bool(expected_issuer and issuer == expected_issuer),
            'issuer_configured': isinstance(issuer, str),
            'pkce_s256_declared': isinstance(methods, list) and 'S256' in methods,
            'findings': issues}


def audit_jwks(jwks: Mapping[str, Any], *, old_jwks: Mapping[str, Any] | None = None) -> dict[str, Any]:
    keys = jwks.get('keys')
    if not isinstance(keys, list) or len(keys) > 64:
        raise OIDCSafetyError('JWKS must contain at most 64 public keys')
    seen: set[str] = set()
    duplicates = set()
    warnings: list[dict[str, str]] = []
    public_keys: list[dict[str, str]] = []
    for key in keys:
        if not isinstance(key, dict) or not isinstance(key.get('kid'), str):
            warnings.append(_finding('JWKS_NO_KID', 'medium', 'jwks', 'A public key lacks a key ID'))
            continue
        kid = key['kid']
        if kid in seen:
            duplicates.add(kid)
        seen.add(kid)
        kty = key.get('kty')
        if kty == 'RSA' and isinstance(key.get('n'), str):
            try:
                import base64
                modulus = base64.urlsafe_b64decode(key['n']+'='*(-len(key['n'])%4))
                if int.from_bytes(modulus, 'big').bit_length() < 2048:
                    warnings.append(_finding('JWKS_WEAK_RSA', 'medium', 'jwks',
                                             'RSA public key below 2048 bits'))
            except (ValueError, TypeError):
                warnings.append(_finding('JWKS_INVALID_RSA', 'medium', 'jwks', 'Malformed RSA modulus'))
        if kty not in {'RSA','EC'}:
            warnings.append(_finding('JWKS_UNSUPPORTED_KEY', 'medium', 'jwks', 'Non-asymmetric key type found'))
        if any(x in key for x in ('d','p','q','dp','dq','qi','k')):
            warnings.append(_finding('JWKS_PRIVATE_MATERIAL', 'high', 'jwks',
                                     'Private/symmetric key material is present in the JWKS'))
        if key.get('use') not in (None, 'sig') or (key.get('key_ops') and 'verify' not in key['key_ops']):
            warnings.append(_finding('JWKS_NOT_SIGNATURE_KEY', 'low', 'jwks', 'Key is not designated for signature verification'))
        public_keys.append({'kid_sha256': hashlib.sha256(kid.encode()).hexdigest()[:16], 'kty': str(kty)})
    if duplicates:
        warnings.append(_finding('JWKS_DUPLICATE_KID', 'high', 'jwks', 'Duplicate key IDs make verification ambiguous'))
    old_ids = {k.get('kid') for k in old_jwks.get('keys', []) if isinstance(k, dict) and isinstance(k.get('kid'), str)} if old_jwks else set()
    return {'key_count': len(keys), 'keys': public_keys,
            'rotation': {'added_count': len(seen-old_ids), 'removed_count': len(old_ids-seen)} if old_jwks is not None else None,
            'findings': warnings}


def verify_access_token(token: str, jwks: Mapping[str, Any], *, expected_issuer: str,
                        expected_audience: str, leeway: int = 30,
                        required_scopes: tuple[str, ...] = ()) -> dict[str, Any]:
    """Verify a real JOSE signature with pinned asymmetric algorithms and trust claims.

    Never output raw token, kid, subject, claims or raw decoder exceptions.
    """
    if not expected_issuer or not expected_audience or not token or len(token) > 16384:
        raise OIDCSafetyError('JWT verification needs expected issuer, audience and bounded token')
    if not 0 <= leeway <= 120:
        raise OIDCSafetyError('JWT clock skew must be between 0 and 120 seconds')
    try:
        import jwt
        from jwt import PyJWK
    except ImportError as exc:
        raise OIDCSafetyError('Install PyJWT[crypto] to verify JWT signatures') from exc
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        return {'status': 'rejected', 'reason': 'malformed_jwt'}
    alg = header.get('alg')
    kid = header.get('kid')
    if any(key in header for key in ('jku','x5u','jwk','crit')):
        return {'status': 'rejected', 'reason': 'untrusted_or_critical_header'}
    if alg not in ALLOWED_ALGORITHMS or not isinstance(kid, str) or not kid or len(kid)>256:
        return {'status': 'rejected', 'reason': 'algorithm_or_kid_not_allowed'}
    matches = [k for k in jwks.get('keys', []) if isinstance(k, dict) and k.get('kid') == kid]
    if len(matches) != 1:
        return {'status': 'rejected', 'reason': 'missing_or_ambiguous_kid'}
    key_data = matches[0]
    if (key_data.get('kty') not in ('RSA','EC') or
            any(x in key_data for x in ('d','p','q','dp','dq','qi','k')) or
            key_data.get('use') not in (None,'sig') or
            (key_data.get('key_ops') and 'verify' not in key_data['key_ops']) or
            (key_data.get('alg') and key_data['alg'] != alg)):
        return {'status': 'rejected', 'reason': 'key_policy_violation'}
    if (alg.startswith(('RS','PS')) and key_data['kty'] != 'RSA') or (alg.startswith('ES') and key_data['kty'] != 'EC'):
        return {'status': 'rejected', 'reason': 'key_algorithm_mismatch'}
    try:
        key = PyJWK.from_dict(key_data, algorithm=alg).key
        claims = jwt.decode(token, key=key, algorithms=[alg], issuer=expected_issuer,
                            audience=expected_audience, leeway=leeway,
                            options={'require': ['exp', 'iss', 'aud'], 'verify_signature': True})
        if not isinstance(claims, dict):
            return {'status': 'rejected', 'reason': 'malformed_claims'}
    except jwt.ExpiredSignatureError:
        return {'status': 'rejected', 'reason': 'expired'}
    except jwt.InvalidIssuerError:
        return {'status': 'rejected', 'reason': 'issuer_mismatch'}
    except jwt.InvalidAudienceError:
        return {'status': 'rejected', 'reason': 'audience_mismatch'}
    except (jwt.PyJWTError, ValueError, TypeError):
        return {'status': 'rejected', 'reason': 'signature_or_claims_invalid'}
    if required_scopes:
        scope_claim = claims.get('scope', claims.get('scp'))
        actual = set(scope_claim.split()) if isinstance(scope_claim, str) else (
            set(x for x in scope_claim if isinstance(x, str)) if isinstance(scope_claim, list) else set())
        if not set(required_scopes).issubset(actual):
            return {'status': 'rejected', 'reason': 'scope_mismatch'}
    return {'status': 'verified', 'signature_verified': True, 'issuer_verified': True,
            'audience_verified': True, 'expiration_verified': True, 'algorithm': alg}


def full_oidc_audit(spec: dict[str, Any], *, metadata: dict[str, Any] | None = None,
                    jwks: dict[str, Any] | None = None, old_jwks: dict[str, Any] | None = None,
                    expected_issuer: str | None = None, expected_audience: str | None = None,
                    token_env: str | None = None,
                    required_scopes: tuple[str, ...] = ()) -> dict[str, Any]:
    report: dict[str, Any] = {'engine': 'achillesapi-oidc-rc18', 'version': '1.0.0rc18',
                              'network_requests': 0, 'oauth': audit_openapi_oauth(spec),
                              'metadata': audit_metadata(metadata, expected_issuer=expected_issuer) if metadata is not None else None,
                              'jwks': audit_jwks(jwks, old_jwks=old_jwks) if jwks is not None else None,
                              'jwt': {'status': 'not_checked'},
                              'limitations': 'Configuration analysis is not a demonstrated authorization bypass. JWT verified only when provided with pinned trust context.'}
    if token_env:
        if not token_env.isidentifier() or not token_env.isascii():
            raise OIDCSafetyError('Invalid token environment variable name')
        token = os.environ.get(token_env)
        if not token or jwks is None or not expected_audience or not expected_issuer:
            raise OIDCSafetyError('JWT verification requires token env, JWKS, expected audience and issuer')
        report['jwt'] = verify_access_token(token, jwks, expected_issuer=expected_issuer,
                                             expected_audience=expected_audience,
                                             required_scopes=required_scopes)
    return report
