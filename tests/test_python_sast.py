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
