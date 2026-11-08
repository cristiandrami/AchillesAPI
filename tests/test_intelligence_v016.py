"""Regression tests use an API schema unrelated to the legacy Achilles lab."""
import json
from typer.testing import CliRunner
from achillesapi.core.intelligence import sample_value, intelligent_plan, adaptive_queue
from achillesapi.core.openapi import parse_openapi
from achillesapi.cli import app

SPEC = {"openapi":"3.0.3", "info":{"title":"Unrelated API", "version":"1"},
        "paths":{
            "/widgets":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object", "required":["label", "size"], "properties":{"label":{"type":"string", "minLength":4},"size":{"type":"integer"},"private":{"type":"string", "readOnly":True}}}}}},"responses":{"201":{"description":"created","content":{"application/json":{"schema":{"type":"object", "properties":{"widget_ref":{"type":"string"}}}}}}}}},
            "/widgets/{widget_ref}":{"get":{"parameters":[{"name":"widget_ref","in":"path","required":True,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}}}}

def test_schema_sample_nested_and_readonly():
    value, warnings = sample_value({}, {"type":"object", "required":["x", "secret"], "properties":{"x":{"type":"integer"}, "secret":{"type":"string", "readOnly":True}}})
    assert value == {"x":1}
    assert warnings

def test_schema_bounded_cycle():
    value, warnings = sample_value({"components":{"schemas":{"Self":{"type":"object", "properties":{"next":{"$ref":"#/components/schemas/Self"}}, "required":["next"]}}}}, {"$ref":"#/components/schemas/Self"})
    assert "schema_depth_limit" in str(warnings)

def test_independent_dependency():
    plan = intelligent_plan(parse_openapi(SPEC), SPEC)
    assert any(x["target_parameter"] == "widget_ref" for x in plan["candidate_dependencies"])
    assert plan["network_requests_sent"] == 0
    assert plan["operations"][0]["request_bodies"]

def test_adaptive_queue():
    plan = intelligent_plan(parse_openapi(SPEC), SPEC)
    queue = adaptive_queue(plan, [{"operation":"GET /widgets/{widget_ref}", "status":403}])
    assert queue[0]["suggested_check"] == "verify_auth_profile"
    assert queue[0]["automatically_authorized"] is False

def test_intelligent_cli(tmp_path):
    path=tmp_path/"spec.json"; path.write_text(json.dumps(SPEC))
    out=tmp_path/"plan.json"
    result=CliRunner().invoke(app,["intelligent-plan",str(path),"--output",str(out)])
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["network_requests_sent"] == 0

def test_adaptive_cli(tmp_path):
    path=tmp_path/"spec.json"; path.write_text(json.dumps(SPEC))
    obs=tmp_path/"observations.json"; obs.write_text(json.dumps([{"operation":"GET /widgets/{widget_ref}", "status":500}]))
    result=CliRunner().invoke(app,["adaptive-review",str(path),str(obs),"--output",str(tmp_path/"queue.json")])
    assert result.exit_code == 0, result.output
    assert json.loads((tmp_path/"queue.json").read_text())["queue"][0]["reason"] == "server_error"
