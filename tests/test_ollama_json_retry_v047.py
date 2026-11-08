"""Regression tests for malformed Ollama JSON. No external network used."""
import json
from pathlib import Path
import pytest
from achillesapi.ai.local import analyze_with_ollama, LocalAIError
from achillesapi.core.openapi import analyze_openapi_file

EXAMPLE = Path(__file__).parents[1] / 'examples' / 'sample_api.yaml'


def _setup(monkeypatch, responses):
    calls = []
    class Response:
        status = 200
        def __init__(self, payload): self.payload=payload
        def read(self, _): return json.dumps(self.payload).encode()
    class Connection:
        def __init__(self,*_args, **_kwargs): pass
        def request(self,method,path,body,headers):
            calls.append(json.loads(body))
        def getresponse(self): return Response(responses[len(calls)-1])
        def close(self): pass
    monkeypatch.setattr('achillesapi.ai.local.http.client.HTTPConnection',Connection)
    return calls


def test_invalid_json_then_repaired_json(monkeypatch):
    repaired = {'executive_summary':'OK', 'risk_observations':[], 'recommended_tests':[], 'limitations':['Only OpenAPI']}
    calls = _setup(monkeypatch,[
        {'message':{'content':'{"executive_summary":"broken", "risk_observations": ['}, 'done_reason':'length'},
        {'message':{'content':json.dumps(repaired)}, 'done_reason':'stop'},
    ])
    result=analyze_with_ollama(analyze_openapi_file(EXAMPLE),[])
    assert result['executive_summary']=='OK'
    assert len(calls)==2
    assert isinstance(calls[1]['format'],dict)
    assert calls[1]['format']['required']==['executive_summary','risk_observations','recommended_tests','limitations']


def test_double_invalid_json_has_actionable_error(monkeypatch):
    calls=_setup(monkeypatch,[
        {'message':{'content':'{"executive_summary": '}, 'done_reason':'length'},
        {'message':{'content':'{badjson}'}, 'done_reason':'length'},
    ])
    with pytest.raises(LocalAIError,match='dopo il tentativo di correzione'):
        analyze_with_ollama(analyze_openapi_file(EXAMPLE),[])
    assert len(calls)==2


def test_missing_fields_then_repaired_json(monkeypatch):
    repaired = {'executive_summary':'OK', 'risk_observations':[], 'recommended_tests':[], 'limitations':[]}
    calls=_setup(monkeypatch,[
        {'message':{'content':'{"executive_summary": "Only"}'}},
        {'message':{'content':json.dumps(repaired)}},
    ])
    assert analyze_with_ollama(analyze_openapi_file(EXAMPLE),[])['executive_summary']=='OK'
    assert len(calls)==2
