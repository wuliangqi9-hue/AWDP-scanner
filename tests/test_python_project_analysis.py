import json

import awdp_pro_scanner as scanner
from awdp_scanner.analysis import analyze_python_project


def test_cross_file_wrapper_propagates_request_taint_to_shell_sink(tmp_path):
    helper = tmp_path / "helpers.py"
    app = tmp_path / "app.py"
    records = [
        (
            str(helper),
            "import subprocess\n\ndef run_command(value):\n    return subprocess.run(value, shell=True)\n",
        ),
        (
            str(app),
            "from helpers import run_command\nfrom flask import request\n\ndef route():\n"
            "    command = request.args.get('command')\n    return run_command(command)\n",
        ),
    ]

    result = analyze_python_project(records)

    flows = [flow for flow in result["flows"] if flow["family"] == "command_injection"]
    assert flows
    flow = flows[0]
    assert flow["confirmed_source_to_sink"] is True
    assert flow["sink_file"] == str(helper.resolve())
    assert flow["sink_line"] == 4
    assert flow["sources"][0]["file"] == str(app.resolve())
    assert any("route" in symbol for symbol in flow["call_chain"])
    assert any("run_command" in symbol for symbol in flow["call_chain"])
    assert result["per_file"][str(app.resolve())]["slice_lines"] == [5, 6]


def test_parameterized_sql_does_not_create_query_taint_flow(tmp_path):
    app = tmp_path / "app.py"
    content = """from flask import request

def route(cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""

    result = analyze_python_project([(str(app), content)])

    assert not [flow for flow in result["flows"] if flow["family"] == "sqli"]


def test_subprocess_argument_list_without_shell_is_not_command_injection(tmp_path):
    app = tmp_path / "app.py"
    content = """import subprocess
from flask import request

def route():
    value = request.args.get("value")
    return subprocess.run(["echo", value], shell=False)
"""

    result = analyze_python_project([(str(app), content)])

    assert not [flow for flow in result["flows"] if flow["family"] == "command_injection"]


def test_direct_ssrf_flow_has_source_and_sink_lines(tmp_path):
    app = tmp_path / "app.py"
    content = """import requests
from flask import request

def proxy():
    url = request.args.get("url")
    return requests.get(url)
"""

    result = analyze_python_project([(str(app), content)])

    flow = next(flow for flow in result["flows"] if flow["family"] == "ssrf")
    assert flow["sources"][0]["line"] == 5
    assert flow["sink_line"] == 6


def test_bottle_route_parameter_flows_through_json_to_mongo_query(tmp_path):
    app = tmp_path / "app.py"
    content = """from bottle import get
import json

@get('/user/<username>')
def user_details(username):
    username_json = json.loads(username)
    return db.user.find({"user": username_json})
"""

    result = analyze_python_project([(str(app), content)])

    flow = next(flow for flow in result["flows"] if flow["family"] == "sqli")
    assert flow["confirmed_source_to_sink"] is True
    assert flow["sources"][0]["name"] == "route:username"
    assert flow["sink"] == "db.user.find"
    assert flow["sink_line"] == 7


def test_plain_function_parameter_is_not_assumed_to_be_http_input(tmp_path):
    app = tmp_path / "app.py"
    content = """def repository_lookup(username):
    return db.user.find({"user": username})
"""

    result = analyze_python_project([(str(app), content)])

    flows = [flow for flow in result["flows"] if flow["family"] == "sqli"]
    assert not flows


def test_bottle_json_mass_assignment_creates_auth_review_flow(tmp_path):
    app = tmp_path / "app.py"
    content = """from bottle import request, route

@route('/users/<uid:int>', method='PUT')
def set_user(uid):
    changes = request.json
    entry = {}
    for attribute, value in changes.items():
        entry[attribute] = value
    return entry
"""

    result = analyze_python_project([(str(app), content)])

    flow = next(flow for flow in result["flows"] if flow["family"] == "auth")
    assert flow["confirmed_source_to_sink"] is True
    assert flow["sink"] == "dynamic-field-assignment"
    assert any(source["name"] == "request.json" for source in flow["sources"])


def test_command_line_configuration_path_is_retained_but_not_awdp_actionable(tmp_path):
    app = tmp_path / "app.py"
    content = """import sys

def load_config(path):
    return open(path).read()

config = load_config(sys.argv[1])
"""

    result = analyze_python_project([(str(app), content)])

    assert not [flow for flow in result["flows"] if flow["family"] == "path_traversal"]
    config_flow = next(flow for flow in result["configuration_flows"] if flow["family"] == "path_traversal")
    assert config_flow["source_scope"] == "deployment_config"
    assert config_flow["confirmed_source_to_sink"] is True


def test_request_cookie_comparison_in_session_validator_is_auth_boundary(tmp_path):
    app = tmp_path / "app.py"
    content = """from flask import request

def get_session_username():
    session_id = request.cookies.get('sessionid')
    username, token = session_id.rsplit(':', 1)
    expected = make_token(username)
    if token == expected:
        return username
    return None

def make_token(username):
    return sha1(KEY + username)
"""

    result = analyze_python_project([(str(app), content)])

    flow = next(flow for flow in result["flows"] if flow["sink"] == "auth-boundary-comparison")
    assert flow["family"] == "auth"
    assert any("request.cookies" in source["name"] for source in flow["sources"])


def test_nested_decorator_wrapper_participates_in_cross_file_auth_flow(tmp_path):
    verifier = tmp_path / "authentication.py"
    app = tmp_path / "app.py"
    verifier_code = """def verify_token(token):
    expected = sign(token)
    if token == expected:
        return 'user'
    return None
"""
    app_code = """from bottle import request
import authentication

def ensure_valid_token(func):
    def wrapper(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        user = authentication.verify_token(token)
        return func(user, *args, **kwargs)
    return wrapper
"""

    result = analyze_python_project([(str(verifier), verifier_code), (str(app), app_code)])

    flow = next(flow for flow in result["flows"] if flow["family"] == "auth")
    assert any("ensure_valid_token.wrapper" in symbol for symbol in flow["call_chain"])
    assert any("request.headers" in source["name"] for source in flow["sources"])


def test_semantic_flow_forces_model_safe_result_to_manual_review(tmp_path, monkeypatch):
    helper = tmp_path / "helpers.py"
    app = tmp_path / "app.py"
    helper_code = "import subprocess\n\ndef run_command(value):\n    return subprocess.run(value, shell=True)\n"
    app_code = (
        "from helpers import run_command\nfrom flask import request\n\ndef route():\n"
        "    command = request.args.get('command')\n    return run_command(command)\n"
    )
    records = [(str(helper), helper_code), (str(app), app_code)]
    project_context = scanner.build_project_context(records)

    def fake_model(_prompt, _num_predict, retries=scanner.MODEL_RETRIES, output_schema=None):
        del retries
        if output_schema == scanner.DETECTION_OUTPUT_SCHEMA:
            return {
                "ok": True,
                "text": json.dumps(
                    {
                        "verdict": "safe",
                        "vuln_type": "",
                        "reason": "model missed wrapper",
                        "code_evidence": "none",
                        "confidence": 0.9,
                    }
                ),
                "error": "",
            }
        return {
            "ok": True,
            "text": json.dumps(
                {
                    "report_fix_summary": "disable shell execution",
                    "vuln_location": "run_command",
                    "original_code_snippet": "subprocess.run(value, shell=True)",
                    "fixed_code_snippet": "subprocess.run([value], shell=False)",
                }
            ),
            "error": "",
        }

    monkeypatch.setattr(scanner, "call_ollama", fake_model)

    result = scanner.audit_single_file(str(helper), helper_code, None, project_context)

    assert result["entry"]["suspected"] == "待人工复核"
    assert result["entry"]["semantic_backend"] == "python-ast-v2"
    assert result["entry"]["semantic_flows_data"]
    assert "AST" in result["entry"]["detection_basis"]
    assert "source→sink" in result["entry"]["reason"]


def test_deployment_only_path_flow_suppresses_lexical_secondary_path_finding():
    code = """from bottle import request
changes = request.json
with open(filename, 'rb') as handle:
    data = handle.read()
"""
    plan = {
        "lang_ctx": scanner.get_language_context(".py", code),
        "semantic_flows": [{"family": "auth"}],
        "configuration_flows": [{"family": "path_traversal"}],
    }

    result = scanner.collect_secondary_findings(
        "app.py",
        code,
        plan,
        {"verdict": "needs_manual_review", "vuln_type": "auth"},
    )

    families = {item["family"] for item in result["findings"] + result["potential_findings"]}
    assert "path_traversal" not in families
