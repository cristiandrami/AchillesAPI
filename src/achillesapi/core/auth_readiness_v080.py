"""Secret-free local auth profile readiness and OpenAPI scheme matching."""
from __future__ import annotations

from typing import Any
from achillesapi.core.auth import load_authentication_manager
from achillesapi.core.openapi import parse_openapi


def auth_readiness(spec: dict[str, Any], auth_path: str | None) -> dict[str, Any]:
    schemes = parse_openapi(spec).security_schemes
    descriptions = load_authentication_manager(auth_path).describe() if auth_path else []
    available = {str(item['type']) for item in descriptions}
    checked = []
    for item in schemes:
        if item.type == 'http':
            compatible = {'bearer', 'oauth2_client_credentials', 'login_json'} if item.scheme == 'bearer' else {'basic'} if item.scheme == 'basic' else set()
        elif item.type == 'apiKey':
            compatible = {'api_key','cookie'} if item.in_ == 'cookie' else {'api_key'}
        elif item.type in ('oauth2', 'openIdConnect'):
            compatible = {'oauth2_client_credentials','bearer','login_json'}
        else:
            compatible = set()
        matches = sorted(available.intersection(compatible))
        checked.append({'scheme': item.scheme_name,'openapi_type':item.type,
                        'compatible_profile_types':sorted(compatible),
                        'configured_profile_types':matches,
                        'status':'configured_unverified' if matches else 'requires_configuration',
                        'note':'Compatibilità dichiarativa: non verifica scadenza o autorizzazioni dei token.'})
    return {'engine':'achilles-auth-readiness-v080','requests_sent':0,
            'profile_count':len(descriptions),
            'profiles': [{'name':p['name'], 'type':p['type'],
                          'requires_environment_variables':p['environment_variables']}
                         for p in descriptions],
            'schemes':checked,
            'supported_runtime_types':['bearer','api_key','basic','cookie',
                                       'oauth2_client_credentials','login_json'],
            'limitations':['Profilo presente non significa token funzionante.',
                           'OAuth2 dinamico usa solo token endpoint esplicitamente autorizzati e in scope.',
                           'Segreti inline di auth.yaml non sono mai restituiti dal report.']}
