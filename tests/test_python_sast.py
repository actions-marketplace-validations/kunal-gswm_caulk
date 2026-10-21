"""Comprehensive test suite for Python AST Security Analysis (SAST001 & SAST002).

Validates:
- SAST001: SQL injection detection across DB-API, SQLite, and Django sinks.
- SAST002: Command injection detection across always-shell and shell=True sinks.
- Intraprocedural taint tracking, taint propagation, taint clearing, and scope isolation.
- False positive resistance for parameterized queries, static commands, and safe argument lists.
- Import aliasing resolution for modules and functions.
- CLI execution, --category SAST filtering, --disable rule controls, and JSON reporting.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from caulk.cli import (
    EXIT_FINDINGS_BREACH_THRESHOLD,
    EXIT_SUCCESS_CLEAN,
    app,
)
from caulk.config import CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory
from caulk.models import FindingCategory, Severity
from caulk.rules import registry
from caulk.rules.base import ScanContext
from caulk.rules.python_sast import (
    ShellCommandInjectionRule,
    SQLInjectionRule,
    run_sast_analysis,
)


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def _scan_snippet(code: str, tmp_path: Path) -> tuple[list, list]:
    """Helper to scan a Python code snippet and return (sql_findings, shell_findings)."""
    file_path = tmp_path / "target.py"
    file_path.write_text(code, encoding="utf-8")

    discovered = DiscoveredFile(
        path=file_path,
        rel_path="target.py",
        size_bytes=len(code.encode("utf-8")),
    )
    inventory = ProjectInventory(
        root_path=tmp_path,
        files=[discovered],
        ecosystems={"python"},
    )
    context = ScanContext(inventory=inventory, config=CaulkConfig())
    return run_sast_analysis(discovered, context)


# ==============================================================================
# 1. SQL Injection (SAST001) Positive Tests
# ==============================================================================


def test_sql_injection_direct_fstring(tmp_path: Path):
    code = """
def get_user(request):
    user_id = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
"""
    sql_findings, shell_findings = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert len(shell_findings) == 0

    finding = sql_findings[0]
    assert finding.rule_id == "SAST001"
    assert finding.category == FindingCategory.SAST
    assert finding.severity == Severity.HIGH
    assert finding.line_number == 5  # line of cursor.execute(query)
    assert "cursor.execute" in finding.evidence
    assert finding.fingerprint != ""


def test_sql_injection_direct_in_sink_fstring(tmp_path: Path):
    code = """
def get_user(request):
    cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 3


def test_sql_injection_concatenation(tmp_path: Path):
    code = """
def search_products(request):
    term = request.form.get("q")
    sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"
    cursor.execute(sql)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 5


def test_sql_injection_percent_formatting(tmp_path: Path):
    code = """
def get_account(request):
    acc = request.values["acc"]
    query = "SELECT * FROM accounts WHERE id = '%s'" % acc
    cursor.execute(query)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 5


def test_sql_injection_percent_formatting_tuple(tmp_path: Path):
    code = """
def authenticate(request):
    username = request.form["username"]
    role = "admin"
    query = "SELECT * FROM users WHERE user = '%s' AND role = '%s'" % (username, role)
    cursor.execute(query)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 6


def test_sql_injection_format_call(tmp_path: Path):
    code = """
def find_item(request):
    item_id = request.json.get("item_id")
    query = "SELECT * FROM items WHERE id = '{}'".format(item_id)
    cur.execute(query)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 5


def test_sql_injection_from_input_source(tmp_path: Path):
    code = """
def cli_lookup():
    user = input("Enter username: ")
    conn.execute(f"SELECT * FROM users WHERE username = '{user}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 4


def test_sql_injection_from_sys_argv(tmp_path: Path):
    code = """
import sys

def main():
    table = sys.argv[1]
    db.execute(f"SELECT * FROM {table}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 6


def test_sql_injection_from_argv_import_alias(tmp_path: Path):
    code = """
from sys import argv as cli_args

def run():
    target = cli_args[1]
    db.execute(f"DELETE FROM logs WHERE host = '{target}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 6


def test_sql_injection_sqlite_executescript(tmp_path: Path):
    code = """
def run_migration(request):
    script = request.form.get("script")
    conn.executescript(script)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 4
    assert "executescript" in sql_findings[0].evidence


def test_sql_injection_django_raw(tmp_path: Path):
    code = """
def user_view(request):
    name = request.GET.get("name")
    User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 4
    assert "User.objects.raw" in sql_findings[0].evidence


def test_sql_injection_multi_step_intermediate_vars(tmp_path: Path):
    code = """
def process(request):
    raw_val = request.cookies.get("session_user")
    stripped = raw_val.strip()
    lowered = stripped.lower()
    prefix = f"user_{lowered}"
    query = f"SELECT * FROM data WHERE owner = '{prefix}'"
    session.execute(query)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 8


def test_sql_injection_flask_get_json(tmp_path: Path):
    code = """
def api_endpoint(request):
    data = request.get_json()
    user_id = data["id"]
    cursor.execute(f"SELECT * FROM accounts WHERE id = {user_id}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 5


# ==============================================================================
# 2. SQL Injection (SAST001) Negative Tests (False-Positive Controls)
# ==============================================================================


def test_sql_parameterized_query_not_flagged(tmp_path: Path):
    code = """
def get_user_safe(request):
    user_id = request.args.get("id")
    # Parameterized query with %s placeholder and tuple parameter
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_parameterized_query_variable_not_flagged(tmp_path: Path):
    code = """
def get_user_safe(request):
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_static_query_not_flagged(tmp_path: Path):
    code = """
def health_check():
    cursor.execute("SELECT 1")
    conn.execute("SELECT count(*) FROM migrations WHERE applied = true")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_overwritten_variable_clears_taint(tmp_path: Path):
    code = """
def lookup(request):
    user_id = request.args.get("id")
    # Overwritten with a hardcoded constant
    user_id = "default_guest_user"
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_unused_taint_not_flagged(tmp_path: Path):
    code = """
def handler(request):
    user_input = request.args.get("unused")
    cursor.execute("SELECT * FROM items WHERE status = 'active'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_non_db_execute_not_flagged(tmp_path: Path):
    code = """
def run_task(request):
    task_id = request.args.get("task_id")
    # task_runner is not a DB receiver and argument has no SQL keywords
    task_runner.execute(f"task_{task_id}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_comments_and_docstrings_not_flagged(tmp_path: Path):
    code = """
def safe_func(request):
    '''
    cursor.execute(f"SELECT * FROM users WHERE id = {request.args.get('id')}")
    '''
    # cursor.execute(f"SELECT * FROM users WHERE id = {request.args.get('id')}")
    return "ok"
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


# ==============================================================================
# 3. Shell Command Injection (SAST002) Positive Tests
# ==============================================================================


def test_shell_injection_os_system(tmp_path: Path):
    code = """
import os

def ping_host(request):
    host = request.args.get("host")
    os.system(f"ping -c 1 {host}")
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    finding = shell_findings[0]
    assert finding.rule_id == "SAST002"
    assert finding.category == FindingCategory.SAST
    assert finding.severity == Severity.HIGH
    assert finding.line_number == 6
    assert "os.system" in finding.evidence
    assert finding.fingerprint != ""


def test_shell_injection_os_popen(tmp_path: Path):
    code = """
import os

def check_disk(request):
    path = request.form["path"]
    pipe = os.popen("df -h " + path)
    return pipe.read()
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_subprocess_run_shell_true(tmp_path: Path):
    code = """
import subprocess

def run_backup(request):
    dest = request.json.get("destination")
    cmd = f"tar -czf {dest}.tar.gz /data"
    subprocess.run(cmd, shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 7


def test_shell_injection_subprocess_popen_shell_true(tmp_path: Path):
    code = """
import subprocess

def background_proc(request):
    target = request.args.get("target")
    proc = subprocess.Popen(f"traceroute {target}", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_subprocess_call_shell_true(tmp_path: Path):
    code = """
import subprocess

def exec_call(request):
    val = request.headers.get("X-Command")
    subprocess.call(f"echo {val}", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_subprocess_check_output_shell_true(tmp_path: Path):
    code = """
import subprocess

def get_listing(request):
    directory = request.args["dir"]
    out = subprocess.check_output(f"ls -la {directory}", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_subprocess_getoutput(tmp_path: Path):
    code = """
import subprocess

def query_domain(request):
    domain = request.args.get("domain")
    info = subprocess.getoutput(f"whois {domain}")
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_subprocess_getstatusoutput(tmp_path: Path):
    code = """
import subprocess

def check_status(request):
    svc = request.form.get("service")
    status, output = subprocess.getstatusoutput("systemctl status " + svc)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


def test_shell_injection_import_aliases(tmp_path: Path):
    code = """
import subprocess as sp
from os import system as sys_exec

def test_aliases(request):
    cmd = request.args.get("c")
    sp.run(f"echo {cmd}", shell=True)
    sys_exec(f"echo {cmd}")
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 2
    line_numbers = {f.line_number for f in shell_findings}
    assert 7 in line_numbers
    assert 8 in line_numbers


def test_shell_injection_from_subprocess_run_import(tmp_path: Path):
    code = """
from subprocess import run as execute_command

def run_job(request):
    param = request.args.get("param")
    execute_command(f"job.sh {param}", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 6


# ==============================================================================
# 4. Shell Command Injection (SAST002) Negative Tests (False-Positive Controls)
# ==============================================================================


def test_shell_safe_argument_list_not_flagged(tmp_path: Path):
    code = """
import subprocess

def ping_safe(request):
    host = request.args.get("host")
    # Passing arguments as a list without shell=True is safe against command injection
    subprocess.run(["ping", "-c", "1", host])
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_shell_explicit_shell_false_not_flagged(tmp_path: Path):
    code = """
import subprocess

def run_explicit_safe(request):
    val = request.args.get("val")
    subprocess.run(["echo", val], shell=False)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_shell_static_command_not_flagged(tmp_path: Path):
    code = """
import os
import subprocess

def system_cleanup():
    os.system("rm -rf /tmp/scratch_*")
    subprocess.run("ls -la /tmp", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_shell_unrelated_system_method_not_flagged(tmp_path: Path):
    code = """
def monitor_metrics(request):
    metric = request.args.get("metric")
    # metrics_collector is not the 'os' module
    metrics_collector.system(metric)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_shell_unused_input_not_flagged(tmp_path: Path):
    code = """
import os

def handle_request(request):
    user_val = request.args.get("name")
    os.system("echo Static message")
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


# ==============================================================================
# 5. Scope Isolation and Branching Tests
# ==============================================================================


def test_scope_isolation_between_functions(tmp_path: Path):
    code = """
def func_a(request):
    tainted = request.args.get("input")
    return tainted

def func_b():
    # func_b has clean scope; tainted from func_a does not leak here
    cursor.execute("SELECT * FROM users")
    os.system("ls")
"""
    sql, shell = _scan_snippet(code, tmp_path)
    assert len(sql) == 0
    assert len(shell) == 0


def test_scope_isolation_in_classes(tmp_path: Path):
    code = """
class Worker:
    def tainted_method(self, request):
        self.val = request.args.get("id")

    def clean_method(self):
        cmd = "ls -la"
        os.system(cmd)
"""
    sql, shell = _scan_snippet(code, tmp_path)
    assert len(sql) == 0
    assert len(shell) == 0


def test_branching_if_else_taint_propagation(tmp_path: Path):
    code = """
def branch_test(request, flag):
    if flag:
        q = request.args.get("user")
    else:
        q = "guest"
    # q is tainted on at least one execution path
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")
"""
    sql, _ = _scan_snippet(code, tmp_path)
    assert len(sql) == 1
    assert sql[0].line_number == 8


# ==============================================================================
# 6. Robustness and Error Recovery Tests
# ==============================================================================


def test_syntax_error_handled_gracefully(tmp_path: Path):
    code = """
def broken_syntax(
    # Missing closing parenthesis and colon
"""
    sql, shell = _scan_snippet(code, tmp_path)
    assert sql == []
    assert shell == []


def test_non_python_file_ignored(tmp_path: Path):
    rule_sql = SQLInjectionRule()
    rule_shell = ShellCommandInjectionRule()

    js_file = DiscoveredFile(path=tmp_path / "app.js", rel_path="app.js", size_bytes=50)
    assert not rule_sql.applies_to_file(js_file)
    assert not rule_shell.applies_to_file(js_file)

    py_file = DiscoveredFile(path=tmp_path / "app.py", rel_path="app.py", size_bytes=50)
    assert rule_sql.applies_to_file(py_file)
    assert rule_shell.applies_to_file(py_file)


def test_rules_registered_in_default_registry():
    r1 = registry.get("SAST001")
    assert r1 is not None
    assert r1.title == "Python SQL Injection"
    assert r1.category == FindingCategory.SAST

    r2 = registry.get("SAST002")
    assert r2 is not None
    assert r2.title == "Command Injection via Shell Execution"
    assert r2.category == FindingCategory.SAST


# ==============================================================================
# 7. CLI End-to-End Tests
# ==============================================================================


def test_cli_scan_with_category_sast(cli_runner: CliRunner, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target_py = repo / "vuln.py"
    target_py.write_text(
        """
def handler(request):
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
""",
        encoding="utf-8",
    )

    result = cli_runner.invoke(app, ["scan", str(repo), "--category", "SAST"])
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    assert "SAST001" in result.output
    # No other rule categories run
    assert "SEC" not in result.output
    assert "CFG" not in result.output


def test_cli_scan_disable_rule(cli_runner: CliRunner, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target_py = repo / "vuln.py"
    target_py.write_text(
        """
import os

def handler(request):
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    os.system(f"ping {uid}")
""",
        encoding="utf-8",
    )

    # Disable SAST001, so only SAST002 should trigger
    result = cli_runner.invoke(
        app,
        ["scan", str(repo), "--category", "SAST", "--disable", "SAST001"],
    )
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    assert "SAST001" not in result.output
    assert "SAST002" in result.output


def test_cli_scan_severity_threshold_filtering(cli_runner: CliRunner, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target_py = repo / "vuln.py"
    target_py.write_text(
        """
def handler(request):
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
""",
        encoding="utf-8",
    )

    # High severity finding with CRITICAL threshold should exit 0 (threshold not breached)
    result = cli_runner.invoke(
        app,
        ["scan", str(repo), "--severity-threshold", "CRITICAL"],
    )
    assert result.exit_code == EXIT_SUCCESS_CLEAN
    assert "SAST001" in result.output


def test_cli_scan_json_output_schema(cli_runner: CliRunner, tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target_py = repo / "app.py"
    target_py.write_text(
        """
import os

def run(request):
    cmd = request.form["cmd"]
    os.system(f"echo {cmd}")
""",
        encoding="utf-8",
    )

    out_json = tmp_path / "report.json"
    result = cli_runner.invoke(
        app,
        ["scan", str(repo), "--format", "json", "--output", str(out_json)],
    )
    assert result.exit_code == EXIT_FINDINGS_BREACH_THRESHOLD
    assert out_json.exists()

    report_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert report_data["summary"]["total_findings"] >= 1
    sast_finding = next(f for f in report_data["findings"] if f["rule_id"] == "SAST002")
    assert sast_finding["category"] == "SAST"
    assert sast_finding["severity"] == "HIGH"
    assert sast_finding["file_path"] == "app.py"
    assert sast_finding["line_number"] == 6
    assert "os.system" in sast_finding["evidence"]


# ==============================================================================
# 8. Scope, Dataflow, and Edge-Case Regression Corpus (Prompt Scenarios 1-10)
# ==============================================================================


def test_scenario_1_tainted_input_transformed_reassigned_to_sink(tmp_path: Path):
    """Scenario 1: Tainted input assigned, transformed via string methods, reassigned, reaching sink."""
    code = """
def handler(request):
    raw_val = request.args.get("id")
    cleaned = raw_val.strip()
    upper = cleaned.upper()
    final_query = f"SELECT * FROM accounts WHERE id = '{upper}'"
    cursor.execute(final_query)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 7


def test_scenario_2_taint_on_one_branch_constant_on_other(tmp_path: Path):
    """Scenario 2: Variable tainted on one branch and overwritten with constant on another."""
    code = """
import os

def branch_merge(request, flag):
    if flag:
        cmd = request.args.get("c")
    else:
        cmd = "echo constant"
    os.system(cmd)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    # Conservative merge keeps taint reachable from the if branch
    assert len(shell_findings) == 1


def test_scenario_3_branches_assigning_different_values(tmp_path: Path):
    """Scenario 3: Variable assigned different tainted values in if/else branches and used after."""
    code = """
def branch_choice(request, mode):
    if mode == "admin":
        tbl = request.args.get("t1")
    else:
        tbl = request.form.get("t2")
    cursor.execute(f"SELECT * FROM {tbl}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1


def test_scenario_4_try_except_finally_reachable_taint(tmp_path: Path):
    """Scenario 4: Taint propagation through try/except/finally preserves reachable values."""
    code = """
import os

def cleanup_sink(request):
    try:
        cmd = request.args.get("c")
    except Exception:
        cmd = "fallback"
    finally:
        os.system(cmd)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert shell_findings[0].line_number == 10


def test_scenario_4_finally_overwritten_clears_taint(tmp_path: Path):
    """Scenario 4b: If finally unconditionally overwrites variable with constant, taint is cleared."""
    code = """
import os

def safe_finally(request):
    try:
        cmd = request.args.get("c")
    finally:
        cmd = "echo safe"
    os.system(cmd)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_scenario_5_loop_variable_tuple_unpacking(tmp_path: Path):
    """Scenario 5: Tainted iterable assigned to unpacked loop variables."""
    code = """
def loop_items(request):
    for key, val in request.form.items():
        cursor.execute(f"SELECT * FROM settings WHERE key = '{key}' AND val = '{val}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1


def test_scenario_6_variable_reassignment_clears_taint(tmp_path: Path):
    """Scenario 6: Variable reassigned to a safe constant clears prior taint."""
    code = """
import os

def clear_taint(request):
    cmd = request.args.get("c")
    cmd = "echo clean"
    os.system(cmd)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_scenario_7_module_vs_function_local_scope(tmp_path: Path):
    """Scenario 7: Module-level tainted variable vs function-local safe variable with same name."""
    code = """
import os

# Module level tainted variable
val = request.args.get("val")

def safe_function():
    val = "echo safe"
    os.system(val)

def unsafe_function(request):
    val = request.args.get("val")
    os.system(val)

os.system(val)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    # safe_function() must NOT trigger; unsafe_function() and module level MUST trigger
    assert len(shell_findings) == 2
    lines = {f.line_number for f in shell_findings}
    assert 13 in lines  # inside unsafe_function
    assert 15 in lines  # at module level


def test_scenario_8_imports_declared_in_branch_and_nested_scope(tmp_path: Path):
    """Scenario 8: Imports declared inside if blocks preserved, but isolated across functions."""
    code = """
def dynamic_import(request, cond):
    if cond:
        import os as shell_runner
    shell_runner.system(request.args.get("c"))

def nested_scope(request):
    def inner():
        import os as local_runner
        local_runner.system(request.args.get("c"))
    inner()
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 2


def test_scenario_9_calls_nested_inside_expressions(tmp_path: Path):
    """Scenario 9: Sinks nested inside return statements and conditional tests."""
    code = """
import os

def check_command(request):
    if os.system(request.args.get("c")) == 0:
        return True
    return False

def return_query(request):
    return cursor.execute(f"SELECT * FROM items WHERE id = {request.args['id']}")
"""
    sql_findings, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1
    assert len(sql_findings) == 1


def test_scenario_10_repeated_scans_same_scan_context(tmp_path: Path):
    """Scenario 10: Repeated scans on same ScanContext yield stable results without cache contamination."""
    file_a = tmp_path / "a.py"
    file_a.write_text(
        "def h(request): cursor.execute(f'SELECT * FROM u WHERE id = {request.args[\"id\"]}')",
        encoding="utf-8",
    )

    file_b = tmp_path / "b.py"
    file_b.write_text("def h(): cursor.execute('SELECT 1')", encoding="utf-8")

    disc_a = DiscoveredFile(path=file_a, rel_path="a.py", size_bytes=file_a.stat().st_size)
    disc_b = DiscoveredFile(path=file_b, rel_path="b.py", size_bytes=file_b.stat().st_size)

    inventory = ProjectInventory(root_path=tmp_path, files=[disc_a, disc_b], ecosystems={"python"})
    context = ScanContext(inventory=inventory, config=CaulkConfig())

    sql_a1, shell_a1 = run_sast_analysis(disc_a, context)
    sql_b1, shell_b1 = run_sast_analysis(disc_b, context)

    # Second pass with same context
    sql_a2, shell_a2 = run_sast_analysis(disc_a, context)
    sql_b2, shell_b2 = run_sast_analysis(disc_b, context)

    assert len(sql_a1) == 1
    assert len(sql_a2) == 1
    assert len(sql_b1) == 0
    assert len(sql_b2) == 0
    assert sql_a1[0].fingerprint == sql_a2[0].fingerprint


# ==============================================================================
# 9. SQL Injection Audit (SAST001) Precision Tests
# ==============================================================================


def test_sql_dynamic_string_with_second_parameter_present(tmp_path: Path):
    """Unsafe dynamic SQL formatted in first argument is flagged even with second params arg."""
    code = """
def query_with_extra_arg(request):
    uid = request.args.get("id")
    status = "active"
    cursor.execute(f"SELECT * FROM users WHERE id = '{uid}' AND status = %s", (status,))
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert sql_findings[0].line_number == 5


def test_sql_keyword_arguments_sinks(tmp_path: Path):
    """SQL sink called with keyword arguments statement= or raw_query=."""
    code = """
def query_kw(request):
    uid = request.args.get("id")
    cursor.execute(statement=f"SELECT * FROM users WHERE id = {uid}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1


def test_sql_uncommon_receiver_with_sql_keyword(tmp_path: Path):
    """Database receiver with uncommon name executing SQL keyword query is detected."""
    code = """
def query_custom_repo(request):
    tbl = request.args.get("table")
    repo.execute(f"SELECT * FROM {tbl}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1


def test_sql_unrelated_objects_methods_not_flagged(tmp_path: Path):
    """Unrelated objects exposing execute, executemany, or raw without SQL keywords are NOT flagged."""
    code = """
def harmless_calls(request):
    data = request.args.get("data")
    camera.raw(data)
    audio_stream.raw(data)
    task_runner.execute(f"run_task_{data}")
    http_client.execute(f"/api/v1/{data}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


def test_sql_multiple_sinks_on_same_line(tmp_path: Path):
    """Multiple SQL sinks on the same line must both be detected with distinct fingerprints."""
    code = """
def multi_query(request):
    a = request.args['a']; b = request.args['b']
    cursor.execute(f"SELECT 1 FROM {a}"); cursor.execute(f"SELECT 2 FROM {b}")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 2
    assert sql_findings[0].fingerprint != sql_findings[1].fingerprint


def test_sql_multiline_evidence_preserves_query_context(tmp_path: Path):
    """Multiline sink call evidence includes the full call expression rather than just cursor.execute(."""
    code = """
def multiline_sql(request):
    cursor.execute(
        f"SELECT * FROM users WHERE id = '{request.args.get('id')}'"
    )
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    assert "SELECT * FROM users" in sql_findings[0].evidence
    assert sql_findings[0].line_number == 3


def test_sql_tainted_data_not_reaching_sink(tmp_path: Path):
    """Tainted input that is never passed to any SQL sink produces no findings."""
    code = """
def safe_flow(request):
    name = request.args.get("name")
    print(f"Logged user: {name}")
    cursor.execute("SELECT * FROM users")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0


# ==============================================================================
# 10. Command Injection Audit (SAST002) Precision Tests
# ==============================================================================


def test_shell_subprocess_safe_list_arguments_not_flagged(tmp_path: Path):
    """Ordinary subprocess calls passing separate arguments without shell=True are safe."""
    code = """
import subprocess

def safe_run(request):
    user_file = request.args.get("file")
    subprocess.run(["ls", "-la", user_file])
    subprocess.run(["cat", user_file], shell=False)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 0


def test_shell_subprocess_shell_true_keyword_argument(tmp_path: Path):
    """Subprocess with shell=True passed via keyword argument args= is flagged."""
    code = """
import subprocess

def vuln_run(request):
    cmd = request.args.get("cmd")
    subprocess.run(args=f"echo {cmd}", shell=True)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 1


def test_shell_multiple_sinks_on_same_line(tmp_path: Path):
    """Multiple shell sinks on the same line must both be detected with distinct fingerprints."""
    code = """
import os

def multi_shell(request):
    c1 = request.args['c1']; c2 = request.args['c2']
    os.system(c1); os.system(c2)
"""
    _, shell_findings = _scan_snippet(code, tmp_path)
    assert len(shell_findings) == 2
    assert shell_findings[0].fingerprint != shell_findings[1].fingerprint


# ==============================================================================
# 11. AST Robustness, Encoding, and Error Handling
# ==============================================================================


def test_ast_robustness_syntax_error_file_does_not_break_valid_files(tmp_path: Path):
    """A syntax error in one file must not crash scanning of other valid files."""
    file_bad = tmp_path / "broken.py"
    file_bad.write_text("def invalid syntax (():", encoding="utf-8")

    file_good = tmp_path / "good.py"
    file_good.write_text(
        "def h(request): cursor.execute(f'SELECT * FROM u WHERE id = {request.args[\"id\"]}')",
        encoding="utf-8",
    )

    disc_bad = DiscoveredFile(
        path=file_bad, rel_path="broken.py", size_bytes=file_bad.stat().st_size
    )
    disc_good = DiscoveredFile(
        path=file_good, rel_path="good.py", size_bytes=file_good.stat().st_size
    )

    inventory = ProjectInventory(
        root_path=tmp_path, files=[disc_bad, disc_good], ecosystems={"python"}
    )
    context = ScanContext(inventory=inventory, config=CaulkConfig())

    sql_bad, _ = run_sast_analysis(disc_bad, context)
    sql_good, _ = run_sast_analysis(disc_good, context)

    assert len(sql_bad) == 0
    assert len(sql_good) == 1


def test_ast_robustness_unicode_identifiers_and_queries(tmp_path: Path):
    """Unicode identifiers and strings are properly tracked and analyzed."""
    code = """
def traitement(request):
    données = request.args.get("nom")
    requête = f"SELECT * FROM utilisateurs WHERE nom = '{données}'"
    cursor.execute(requête)
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1


def test_ast_robustness_empty_and_comment_files(tmp_path: Path):
    """Empty files and files containing only comments or docstrings produce 0 findings."""
    code = """# Just a comment file
\"\"\"Docstring only\"\"\"
"""
    sql_findings, shell_findings = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0
    assert len(shell_findings) == 0


def test_ast_robustness_deeply_nested_expressions_safety(tmp_path: Path):
    """Deeply nested expressions that trigger RecursionError are handled safely without crashing."""
    # Build a file with nested parentheses
    nested = "(" * 2000 + "1" + ")" * 2000
    code = f"x = {nested}\n"
    sql_findings, shell_findings = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 0
    assert len(shell_findings) == 0


# ==============================================================================
# 12. Finding Quality and Evidence Redaction
# ==============================================================================


def test_finding_evidence_redacts_embedded_secret(tmp_path: Path):
    """Secrets embedded in source lines containing sinks are redacted in finding evidence."""
    code = """
def handler(request):
    cursor.execute(f"SELECT * FROM audit WHERE token = 'ghp_EXAMPLETOKENFORTESTINGONLY1234567890' AND user = '{request.args.get('u')}'")
"""
    sql_findings, _ = _scan_snippet(code, tmp_path)
    assert len(sql_findings) == 1
    # Evidence must NOT expose the raw token
    assert "ghp_EXAMPLETOKENFORTESTINGONLY1234567890" not in sql_findings[0].evidence
    assert "[REDACTED" in sql_findings[0].evidence


def test_cli_disable_case_insensitive_flag(cli_runner: CliRunner, tmp_path: Path):
    """CLI --disable flag is case-insensitive for SAST rules."""
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text(
        "def h(request): cursor.execute(f'SELECT * FROM u WHERE id = {request.args[\"id\"]}')",
        encoding="utf-8",
    )

    result = cli_runner.invoke(app, ["scan", str(repo), "--disable", "sast001"])
    assert "SAST001" not in result.output


# ==============================================================================
# 13. SAST Coverage Gaps, Diagnostics, and Scan Completeness
# ==============================================================================


def test_ast_parse_recursion_error_records_diagnostic_and_marks_incomplete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """AST parsing RecursionError is recorded in diagnostics and marks scan incomplete."""
    from caulk.scanner import CaulkScanner

    file_deep = tmp_path / "deep.py"
    file_deep.write_text("x = 1\n", encoding="utf-8")

    file_good = tmp_path / "good.py"
    file_good.write_text(
        "def handler(request):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {request.args[\"id\"]}')\n",
        encoding="utf-8",
    )

    orig_parse = ast.parse

    def controlled_parse(source, *args, **kwargs):
        filename = kwargs.get("filename") or (args[0] if len(args) > 0 else "")
        if "deep.py" in str(filename):
            raise RecursionError("maximum recursion depth exceeded during parsing")
        return orig_parse(source, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", controlled_parse)

    scanner = CaulkScanner(CaulkConfig())
    result = scanner.scan(tmp_path)

    assert result.summary.is_complete is False
    assert len(result.errors) >= 1
    assert any(
        "AST parsing failed for deep.py: maximum recursion depth exceeded (RecursionError)" in e
        for e in result.errors
    )
    # Source contents must not be exposed in diagnostics
    assert all("x = 1" not in e for e in result.errors)
    # Valid files must still be analyzed and their findings preserved
    assert len(result.findings) == 1
    assert result.findings[0].file_path == "good.py"
    assert result.findings[0].rule_id == "SAST001"


def test_ast_traversal_recursion_error_retains_partial_findings_and_marks_incomplete(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """AST traversal RecursionError retains findings already discovered and marks scan incomplete."""
    from caulk.rules.python_sast import PythonASTSecurityAnalyzer
    from caulk.scanner import CaulkScanner

    file_two = tmp_path / "two_funcs.py"
    file_two.write_text(
        "def func_vuln(request):\n"
        "    cursor.execute(f'SELECT * FROM users WHERE id = {request.args[\"id\"]}')\n"
        "\n"
        "def func_recurse(request):\n"
        "    os.system(request.args['cmd'])\n",
        encoding="utf-8",
    )

    orig_analyze_stmts = PythonASTSecurityAnalyzer._analyze_statements

    def mock_analyze_statements(self, stmts, *args, **kwargs):
        first_call = getattr(self, "_call_counter", 0)
        self._call_counter = first_call + 1
        if first_call == 0:
            for s in stmts:
                orig_analyze_stmts(self, [s], *args, **kwargs)
                if isinstance(s, ast.FunctionDef) and s.name == "func_vuln":
                    raise RecursionError("maximum recursion depth exceeded during traversal")
        else:
            orig_analyze_stmts(self, stmts, *args, **kwargs)

    monkeypatch.setattr(PythonASTSecurityAnalyzer, "_analyze_statements", mock_analyze_statements)

    scanner = CaulkScanner(CaulkConfig())
    result = scanner.scan(tmp_path)

    assert result.summary.is_complete is False
    assert len(result.errors) >= 1
    assert any(
        "SAST analysis traversal failed for two_funcs.py: maximum recursion depth exceeded (RecursionError)"
        in e
        for e in result.errors
    )
    # Partial finding discovered before RecursionError must be retained
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SAST001"
    # Uninspected sink must not produce finding
    assert not any(f.rule_id == "SAST002" for f in result.findings)


def test_ast_parse_syntax_error_records_diagnostic_safely(tmp_path: Path):
    """SyntaxError records line number and file path without leaking code lines."""
    from caulk.scanner import CaulkScanner

    bad_file = tmp_path / "syntax_error.py"
    bad_file.write_text(
        "def broken_fn(:\n    secret_value = 'SUPER_SECRET_12345'\n", encoding="utf-8"
    )

    scanner = CaulkScanner(CaulkConfig())
    result = scanner.scan(tmp_path)

    assert result.summary.is_complete is False
    assert len(result.errors) >= 1
    assert any(
        "AST parsing failed for syntax_error.py: syntax error on line 1" in e for e in result.errors
    )
    # Diagnostic must not leak source line content or secret values
    assert all("SUPER_SECRET_12345" not in e for e in result.errors)
    assert all("broken_fn" not in e for e in result.errors)


def test_ast_parse_value_or_type_error_records_diagnostic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """ValueError during parsing records error class name safely."""
    from caulk.scanner import CaulkScanner

    bad_file = tmp_path / "bad_val.py"
    bad_file.write_text("a = 1\n", encoding="utf-8")

    orig_parse = ast.parse

    def mock_parse(source, *args, **kwargs):
        filename = kwargs.get("filename") or (args[0] if len(args) > 0 else "")
        if "bad_val.py" in str(filename):
            raise ValueError("null bytes in input")
        return orig_parse(source, *args, **kwargs)

    monkeypatch.setattr(ast, "parse", mock_parse)

    scanner = CaulkScanner(CaulkConfig())
    result = scanner.scan(tmp_path)

    assert result.summary.is_complete is False
    assert any("AST parsing failed for bad_val.py: ValueError" in e for e in result.errors)


def test_ast_non_python_files_do_not_produce_sast_diagnostics(tmp_path: Path):
    """Non-Python files do not trigger AST parsing or false analysis incomplete status."""
    from caulk.scanner import CaulkScanner

    (tmp_path / "config.json").write_text('{"name": "test"}', encoding="utf-8")
    (tmp_path / "script.js").write_text("console.log('hello');", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Readme", encoding="utf-8")

    scanner = CaulkScanner(CaulkConfig())
    result = scanner.scan(tmp_path)

    assert result.summary.is_complete is True
    assert result.errors == []


def test_repeated_scans_do_not_leak_diagnostics(tmp_path: Path):
    """Separate scan invocations maintain isolated diagnostic state."""
    from caulk.scanner import CaulkScanner

    dir1 = tmp_path / "scan1"
    dir1.mkdir()
    (dir1 / "bad.py").write_text("def f(:", encoding="utf-8")

    dir2 = tmp_path / "scan2"
    dir2.mkdir()
    (dir2 / "clean.py").write_text("x = 1\n", encoding="utf-8")

    scanner = CaulkScanner(CaulkConfig())

    res1 = scanner.scan(dir1)
    assert res1.summary.is_complete is False
    assert len(res1.errors) == 1

    res2 = scanner.scan(dir2)
    assert res2.summary.is_complete is True
    assert res2.errors == []
