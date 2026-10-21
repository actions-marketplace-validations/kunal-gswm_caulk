"""Deterministic AST-based static application security testing (SAST) for Python.

Detects:
- SAST001: SQL injection via dynamic query string formatting passed to database drivers.
- SAST002: Command injection via unsanitized values passed to shell execution functions.

Features intraprocedural taint tracking, import aliasing resolution, false-positive controls,
and zero external AST dependencies.
"""

from __future__ import annotations

import ast
import re

from caulk.discovery import DiscoveredFile
from caulk.models import Confidence, Finding, FindingCategory, Severity, compute_fingerprint
from caulk.redaction import sanitize_evidence
from caulk.rules.base import Rule, ScanContext

# Default module and symbol tracking
DEFAULT_MODULE_ALIASES: dict[str, str] = {
    "os": "os",
    "subprocess": "subprocess",
    "sys": "sys",
}

DEFAULT_REQUEST_NAMES: set[str] = {"request", "req"}
DEFAULT_ARGV_NAMES: set[str] = {"argv"}

REQUEST_ATTRIBUTES: set[str] = {
    "args",
    "form",
    "values",
    "cookies",
    "json",
    "data",
    "GET",
    "POST",
    "COOKIES",
    "headers",
    "body",
    "files",
    "FILES",
    "META",
    "params",
}

STRONG_DB_RECEIVERS: set[str] = {
    "cursor",
    "cur",
    "conn",
    "connection",
    "db",
    "database",
}

DB_RECEIVER_SUBSTRINGS: set[str] = {
    "cursor",
    "cur",
    "conn",
    "connection",
    "db",
    "database",
    "session",
    "engine",
    "models",
    "objects",
    "db_client",
    "sql_client",
}

SQL_KEYWORDS: set[str] = {
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "CREATE",
    "ALTER",
    "REPLACE",
    "TRUNCATE",
    "MERGE",
    "GRANT",
    "REVOKE",
    "UNION",
    "PRAGMA",
    "EXEC",
    "EXECUTE",
    "CALL",
    "SHOW",
    "DESCRIBE",
    "EXPLAIN",
    "USE",
}

ALWAYS_SHELL_SINKS: set[tuple[str, str]] = {
    ("os", "system"),
    ("os", "popen"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
}

SUBPROCESS_SHELL_SINKS: set[tuple[str, str]] = {
    ("subprocess", "run"),
    ("subprocess", "Popen"),
    ("subprocess", "call"),
    ("subprocess", "check_call"),
    ("subprocess", "check_output"),
}

STRING_METHOD_NAMES: set[str] = {
    "strip",
    "lstrip",
    "rstrip",
    "lower",
    "upper",
    "replace",
    "encode",
    "decode",
    "split",
    "join",
}


def _is_request_receiver(node: ast.AST, request_names: set[str]) -> bool:
    """Check if node represents a request object or alias."""
    if isinstance(node, ast.Name) and node.id in request_names:
        return True
    return bool(isinstance(node, ast.Attribute) and node.attr == "request")


def _is_request_attr(node: ast.AST, request_names: set[str]) -> bool:
    """Check if node represents an attribute access on a request object."""
    if isinstance(node, ast.Attribute) and node.attr in REQUEST_ATTRIBUTES:
        return _is_request_receiver(node.value, request_names)
    return False


def _is_argv_node(node: ast.AST, argv_names: set[str], module_aliases: dict[str, str]) -> bool:
    """Check if node represents sys.argv or an alias of argv."""
    if isinstance(node, ast.Name) and node.id in argv_names:
        return True
    if isinstance(node, ast.Attribute) and node.attr == "argv" and isinstance(node.value, ast.Name):
        mod = module_aliases.get(node.value.id, node.value.id)
        return mod == "sys"
    return False


def _extract_target_names(target: ast.AST) -> list[str]:
    """Recursively collect variable names from assignment or loop targets."""
    names: list[str] = []
    if isinstance(target, ast.Name):
        names.append(target.id)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            names.extend(_extract_target_names(elt))
    return names


def is_taint_source(
    node: ast.AST | None,
    request_names: set[str],
    argv_names: set[str],
    module_aliases: dict[str, str],
) -> bool:
    """Determine if an AST expression node originates directly from an untrusted source."""
    if node is None:
        return False

    # 1. input() or builtins.input() call
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id == "input":
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "input"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "builtins"
        ):
            return True

        # Call to request.get_json()
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get_json"
            and _is_request_receiver(node.func.value, request_names)
        ):
            return True

        # Method calls on request attributes or request.get_json()
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "get",
            "getlist",
            "keys",
            "values",
            "items",
            "pop",
            "popitem",
            "setdefault",
        ):
            receiver = node.func.value
            if _is_request_attr(receiver, request_names):
                return True
            if is_taint_source(receiver, request_names, argv_names, module_aliases):
                return True

    # 2. sys.argv or argv indexing / subscript
    if isinstance(node, ast.Subscript):
        if _is_argv_node(node.value, argv_names, module_aliases):
            return True
        if _is_request_attr(node.value, request_names):
            return True
        if is_taint_source(node.value, request_names, argv_names, module_aliases):
            return True

    # 3. Direct request attributes: request.args, request.form, request.data, request.body, etc.
    if _is_request_attr(node, request_names):
        return True

    # 4. Direct argv reference
    return bool(_is_argv_node(node, argv_names, module_aliases))


def is_expr_tainted(
    expr: ast.AST | None,
    tainted_vars: set[str],
    request_names: set[str],
    argv_names: set[str],
    module_aliases: dict[str, str],
) -> bool:
    """Recursively check whether an expression evaluates to or contains tainted data."""
    if expr is None:
        return False

    # Check direct taint sources
    if is_taint_source(expr, request_names, argv_names, module_aliases):
        return True

    # Variable lookup
    if isinstance(expr, ast.Name):
        return expr.id in tainted_vars

    # Walrus / NamedExpr: (x := expr)
    if isinstance(expr, ast.NamedExpr):
        tainted = is_expr_tainted(
            expr.value, tainted_vars, request_names, argv_names, module_aliases
        )
        if isinstance(expr.target, ast.Name):
            if tainted:
                tainted_vars.add(expr.target.id)
            else:
                tainted_vars.discard(expr.target.id)
        return tainted

    # Ternary / IfExp: body if test else orelse
    if isinstance(expr, ast.IfExp):
        return is_expr_tainted(
            expr.body, tainted_vars, request_names, argv_names, module_aliases
        ) or is_expr_tainted(expr.orelse, tainted_vars, request_names, argv_names, module_aliases)

    # f-string: ast.JoinedStr
    if isinstance(expr, ast.JoinedStr):
        return any(
            is_expr_tainted(val, tainted_vars, request_names, argv_names, module_aliases)
            for val in expr.values
        )

    # Formatted value within f-string
    if isinstance(expr, ast.FormattedValue):
        return is_expr_tainted(expr.value, tainted_vars, request_names, argv_names, module_aliases)

    # Binary operations: string concatenation (+) or % string formatting
    if isinstance(expr, ast.BinOp):
        if isinstance(expr.op, ast.Add):
            return is_expr_tainted(
                expr.left, tainted_vars, request_names, argv_names, module_aliases
            ) or is_expr_tainted(
                expr.right, tainted_vars, request_names, argv_names, module_aliases
            )
        if isinstance(expr.op, ast.Mod):
            if is_expr_tainted(expr.left, tainted_vars, request_names, argv_names, module_aliases):
                return True
            if is_expr_tainted(expr.right, tainted_vars, request_names, argv_names, module_aliases):
                return True
            if isinstance(expr.right, (ast.Tuple, ast.List)):
                return any(
                    is_expr_tainted(elt, tainted_vars, request_names, argv_names, module_aliases)
                    for elt in expr.right.elts
                )
            if isinstance(expr.right, ast.Dict):
                return any(
                    is_expr_tainted(v, tainted_vars, request_names, argv_names, module_aliases)
                    for v in expr.right.values
                    if v is not None
                )
            return False

    # Method calls: .format(...), string methods, or collection methods on tainted objects
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Attribute):
            attr = expr.func.attr
            if attr == "format":
                if is_expr_tainted(
                    expr.func.value, tainted_vars, request_names, argv_names, module_aliases
                ):
                    return True
                if any(
                    is_expr_tainted(arg, tainted_vars, request_names, argv_names, module_aliases)
                    for arg in expr.args
                ):
                    return True
                if any(
                    is_expr_tainted(
                        kw.value, tainted_vars, request_names, argv_names, module_aliases
                    )
                    for kw in expr.keywords
                ):
                    return True
            elif attr in STRING_METHOD_NAMES:
                if is_expr_tainted(
                    expr.func.value, tainted_vars, request_names, argv_names, module_aliases
                ):
                    return True
                if (
                    attr == "join"
                    and expr.args
                    and is_expr_tainted(
                        expr.args[0], tainted_vars, request_names, argv_names, module_aliases
                    )
                ):
                    return True
            elif attr in ("get", "getlist", "pop"):
                if is_expr_tainted(
                    expr.func.value, tainted_vars, request_names, argv_names, module_aliases
                ):
                    return True

        # str(x) call
        if (
            isinstance(expr.func, ast.Name)
            and expr.func.id == "str"
            and expr.args
            and is_expr_tainted(
                expr.args[0], tainted_vars, request_names, argv_names, module_aliases
            )
        ):
            return True

    # Subscripts on tainted collections: tainted_dict['id']
    if isinstance(expr, ast.Subscript):
        return is_expr_tainted(expr.value, tainted_vars, request_names, argv_names, module_aliases)

    # Lists and Tuples: [x] or (x,)
    if isinstance(expr, (ast.List, ast.Tuple)):
        return any(
            is_expr_tainted(elt, tainted_vars, request_names, argv_names, module_aliases)
            for elt in expr.elts
        )

    # Sets: {x}
    if isinstance(expr, ast.Set):
        return any(
            is_expr_tainted(elt, tainted_vars, request_names, argv_names, module_aliases)
            for elt in expr.elts
        )

    # Dicts: {"key": x}
    if isinstance(expr, ast.Dict):
        return any(
            (
                k is not None
                and is_expr_tainted(k, tainted_vars, request_names, argv_names, module_aliases)
            )
            or (
                v is not None
                and is_expr_tainted(v, tainted_vars, request_names, argv_names, module_aliases)
            )
            for k, v in zip(expr.keys, expr.values, strict=False)
        )

    return False


def extract_literal_strings(
    expr: ast.AST | None,
    assigned_literals: dict[str, list[str]],
) -> list[str]:
    """Collect literal string segments from an expression or previously assigned variable."""
    if expr is None:
        return []
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        return [expr.value]
    if isinstance(expr, ast.JoinedStr):
        result: list[str] = []
        for val in expr.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                result.append(val.value)
        return result
    if isinstance(expr, ast.BinOp):
        return extract_literal_strings(expr.left, assigned_literals) + extract_literal_strings(
            expr.right, assigned_literals
        )
    if isinstance(expr, ast.Call):
        if isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
            return extract_literal_strings(expr.func.value, assigned_literals)
        return []
    if isinstance(expr, ast.IfExp):
        return extract_literal_strings(expr.body, assigned_literals) + extract_literal_strings(
            expr.orelse, assigned_literals
        )
    if isinstance(expr, ast.Name):
        return list(assigned_literals.get(expr.id, []))
    return []


def _is_truthy(node: ast.AST | None) -> bool:
    """Check if node evaluates to a statically truthy constant."""
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return bool(isinstance(node, ast.Name) and node.id == "True")


class PythonASTSecurityAnalyzer:
    """Traverses Python AST to identify SQL injection and command injection vulnerabilities."""

    def __init__(self, file: DiscoveredFile, context: ScanContext) -> None:
        self.file = file
        self.context = context
        self.lines = context.get_lines(file)
        self.sql_findings: list[Finding] = []
        self.shell_findings: list[Finding] = []
        self._seen_sql_calls: set[tuple[int, int]] = set()
        self._seen_shell_calls: set[tuple[int, int]] = set()

    def analyze(self, tree: ast.AST) -> tuple[list[Finding], list[Finding]]:
        """Run AST security analysis across the given syntax tree."""
        module_aliases = dict(DEFAULT_MODULE_ALIASES)
        function_aliases: dict[str, tuple[str, str]] = {}
        request_names = set(DEFAULT_REQUEST_NAMES)
        argv_names = set(DEFAULT_ARGV_NAMES)

        try:
            if isinstance(tree, ast.Module):
                self._analyze_statements(
                    tree.body,
                    tainted_vars=set(),
                    assigned_literals={},
                    module_aliases=module_aliases,
                    function_aliases=function_aliases,
                    request_names=request_names,
                    argv_names=argv_names,
                )
        except RecursionError:
            # Safely handle pathological AST nesting depth
            pass

        return self.sql_findings, self.shell_findings

    def _analyze_statements(
        self,
        stmts: list[ast.stmt],
        tainted_vars: set[str],
        assigned_literals: dict[str, list[str]],
        module_aliases: dict[str, str],
        function_aliases: dict[str, tuple[str, str]],
        request_names: set[str],
        argv_names: set[str],
    ) -> None:
        """Intraprocedural statement-by-statement traversal in execution order."""
        for stmt in stmts:
            # 1. Imports
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    name = alias.name
                    asname = alias.asname or name
                    module_aliases[asname] = name
                continue

            if isinstance(stmt, ast.ImportFrom):
                mod = stmt.module or ""
                for alias in stmt.names:
                    name = alias.name
                    asname = alias.asname or name
                    function_aliases[asname] = (mod, name)
                    if mod in ("flask",) and name == "request":
                        request_names.add(asname)
                    if mod in ("sys",) and name == "argv":
                        argv_names.add(asname)
                continue

            # 2. Scope boundaries: Function and AsyncFunction definitions
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_req_names = set(request_names)
                for arg in stmt.args.args:
                    if arg.arg in ("request", "req"):
                        func_req_names.add(arg.arg)

                # Isolated scope for function body
                self._analyze_statements(
                    stmt.body,
                    tainted_vars=set(),
                    assigned_literals={},
                    module_aliases=dict(module_aliases),
                    function_aliases=dict(function_aliases),
                    request_names=func_req_names,
                    argv_names=set(argv_names),
                )
                continue

            # 3. Class definitions
            if isinstance(stmt, ast.ClassDef):
                self._analyze_statements(
                    stmt.body,
                    tainted_vars=set(),
                    assigned_literals={},
                    module_aliases=dict(module_aliases),
                    function_aliases=dict(function_aliases),
                    request_names=set(request_names),
                    argv_names=set(argv_names),
                )
                continue

            # 4. Conditional branches: if / else
            if isinstance(stmt, ast.If):
                # Check sinks and walrus in condition
                self._check_calls_in_node(
                    stmt.test,
                    tainted_vars,
                    assigned_literals,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )

                t_body = set(tainted_vars)
                lit_body = dict(assigned_literals)
                self._analyze_statements(
                    stmt.body,
                    t_body,
                    lit_body,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )

                t_orelse = set(tainted_vars)
                lit_orelse = dict(assigned_literals)
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        t_orelse,
                        lit_orelse,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )

                tainted_vars.clear()
                tainted_vars.update(t_body | t_orelse)
                assigned_literals.update(lit_body)
                assigned_literals.update(lit_orelse)
                continue

            # 5. Exception handling: try / except / finally
            if isinstance(stmt, ast.Try):
                t_body = set(tainted_vars)
                lit_body = dict(assigned_literals)
                self._analyze_statements(
                    stmt.body,
                    t_body,
                    lit_body,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )

                branch_taints: list[set[str]] = [t_body]
                branch_lits: list[dict[str, list[str]]] = [lit_body]

                for handler in stmt.handlers:
                    t_h = set(tainted_vars)
                    lit_h = dict(assigned_literals)
                    self._analyze_statements(
                        handler.body,
                        t_h,
                        lit_h,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )
                    branch_taints.append(t_h)
                    branch_lits.append(lit_h)

                if stmt.orelse:
                    t_o = set(t_body)
                    lit_o = dict(lit_body)
                    self._analyze_statements(
                        stmt.orelse,
                        t_o,
                        lit_o,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )
                    branch_taints.append(t_o)
                    branch_lits.append(lit_o)

                pre_final_taints: set[str] = set()
                for bt in branch_taints:
                    pre_final_taints |= bt

                pre_final_lits: dict[str, list[str]] = dict(assigned_literals)
                for bl in branch_lits:
                    pre_final_lits.update(bl)

                if stmt.finalbody:
                    t_f = set(pre_final_taints)
                    lit_f = dict(pre_final_lits)
                    self._analyze_statements(
                        stmt.finalbody,
                        t_f,
                        lit_f,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )
                    tainted_vars.clear()
                    tainted_vars.update(t_f)
                    assigned_literals.clear()
                    assigned_literals.update(lit_f)
                else:
                    tainted_vars.clear()
                    tainted_vars.update(pre_final_taints)
                    assigned_literals.clear()
                    assigned_literals.update(pre_final_lits)
                continue

            # 6. Loops: for / while
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                if is_expr_tainted(
                    stmt.iter, tainted_vars, request_names, argv_names, module_aliases
                ):
                    for name in _extract_target_names(stmt.target):
                        tainted_vars.add(name)

                self._analyze_statements(
                    stmt.body,
                    tainted_vars,
                    assigned_literals,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        tainted_vars,
                        assigned_literals,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )
                continue

            if isinstance(stmt, ast.While):
                self._check_calls_in_node(
                    stmt.test,
                    tainted_vars,
                    assigned_literals,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )
                self._analyze_statements(
                    stmt.body,
                    tainted_vars,
                    assigned_literals,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )
                if stmt.orelse:
                    self._analyze_statements(
                        stmt.orelse,
                        tainted_vars,
                        assigned_literals,
                        module_aliases,
                        function_aliases,
                        request_names,
                        argv_names,
                    )
                continue

            # 7. With statements
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    if item.optional_vars and is_expr_tainted(
                        item.context_expr,
                        tainted_vars,
                        request_names,
                        argv_names,
                        module_aliases,
                    ):
                        for name in _extract_target_names(item.optional_vars):
                            tainted_vars.add(name)
                self._analyze_statements(
                    stmt.body,
                    tainted_vars,
                    assigned_literals,
                    module_aliases,
                    function_aliases,
                    request_names,
                    argv_names,
                )
                continue

            # 8. Standard statement: Check sinks in calls within statement
            self._check_calls_in_node(
                stmt,
                tainted_vars,
                assigned_literals,
                module_aliases,
                function_aliases,
                request_names,
                argv_names,
            )

            # 9. Update variable taint & literal tracking from assignments
            if isinstance(stmt, ast.Assign):
                # Tuple unpacking assignment: a, b = x, y
                if isinstance(stmt.value, (ast.Tuple, ast.List)):
                    for target in stmt.targets:
                        if isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) == len(
                            stmt.value.elts
                        ):
                            for t_elt, v_elt in zip(target.elts, stmt.value.elts, strict=False):
                                is_t = is_expr_tainted(
                                    v_elt,
                                    tainted_vars,
                                    request_names,
                                    argv_names,
                                    module_aliases,
                                )
                                lits = extract_literal_strings(v_elt, assigned_literals)
                                self._assign_target(
                                    t_elt, is_t, lits, tainted_vars, assigned_literals
                                )
                        else:
                            is_t = is_expr_tainted(
                                stmt.value,
                                tainted_vars,
                                request_names,
                                argv_names,
                                module_aliases,
                            )
                            lits = extract_literal_strings(stmt.value, assigned_literals)
                            self._assign_target(target, is_t, lits, tainted_vars, assigned_literals)
                else:
                    is_t = is_expr_tainted(
                        stmt.value, tainted_vars, request_names, argv_names, module_aliases
                    )
                    lits = extract_literal_strings(stmt.value, assigned_literals)
                    for target in stmt.targets:
                        self._assign_target(target, is_t, lits, tainted_vars, assigned_literals)

            elif isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    is_t = is_expr_tainted(
                        stmt.value, tainted_vars, request_names, argv_names, module_aliases
                    )
                    lits = extract_literal_strings(stmt.value, assigned_literals)
                    self._assign_target(stmt.target, is_t, lits, tainted_vars, assigned_literals)

            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
                is_t = is_expr_tainted(
                    stmt.value, tainted_vars, request_names, argv_names, module_aliases
                )
                if is_t:
                    tainted_vars.add(stmt.target.id)
                lits = extract_literal_strings(stmt.value, assigned_literals)
                if stmt.target.id in assigned_literals:
                    assigned_literals[stmt.target.id].extend(lits)
                else:
                    assigned_literals[stmt.target.id] = lits

    def _assign_target(
        self,
        target: ast.AST,
        is_tainted: bool,
        literals: list[str],
        tainted_vars: set[str],
        assigned_literals: dict[str, list[str]],
    ) -> None:
        """Assign taint state and literals to target variables."""
        if isinstance(target, ast.Name):
            if is_tainted:
                tainted_vars.add(target.id)
            else:
                tainted_vars.discard(target.id)
            assigned_literals[target.id] = literals

        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    if is_tainted:
                        tainted_vars.add(elt.id)
                    else:
                        tainted_vars.discard(elt.id)
                    assigned_literals[elt.id] = literals

    def _collect_named_exprs(self, node: ast.AST) -> list[ast.NamedExpr]:
        """Collect all ast.NamedExpr nodes not inside nested functions/classes."""
        named_exprs: list[ast.NamedExpr] = []
        if isinstance(node, ast.NamedExpr):
            named_exprs.append(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            named_exprs.extend(self._collect_named_exprs(child))
        return named_exprs

    def _check_calls_in_node(
        self,
        node: ast.AST,
        tainted_vars: set[str],
        assigned_literals: dict[str, list[str]],
        module_aliases: dict[str, str],
        function_aliases: dict[str, tuple[str, str]],
        request_names: set[str],
        argv_names: set[str],
    ) -> None:
        """Find and evaluate all Call nodes and NamedExpr nodes within an AST subtree."""
        for named in self._collect_named_exprs(node):
            if isinstance(named.target, ast.Name):
                is_t = is_expr_tainted(
                    named.value, tainted_vars, request_names, argv_names, module_aliases
                )
                lits = extract_literal_strings(named.value, assigned_literals)
                self._assign_target(named.target, is_t, lits, tainted_vars, assigned_literals)

        calls = self._collect_calls(node)
        for call in calls:
            # 1. SQL Injection check
            self._evaluate_sql_sink(
                call,
                tainted_vars,
                assigned_literals,
                request_names,
                argv_names,
                module_aliases,
            )
            # 2. Shell Command Injection check
            self._evaluate_shell_sink(
                call,
                tainted_vars,
                module_aliases,
                function_aliases,
                request_names,
                argv_names,
            )

    def _collect_calls(self, node: ast.AST) -> list[ast.Call]:
        """Collect all ast.Call nodes that are not inside nested functions/classes."""
        calls: list[ast.Call] = []
        if isinstance(node, ast.Call):
            calls.append(node)
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            calls.extend(self._collect_calls(child))
        return calls

    def _evaluate_sql_sink(
        self,
        call: ast.Call,
        tainted_vars: set[str],
        assigned_literals: dict[str, list[str]],
        request_names: set[str],
        argv_names: set[str],
        module_aliases: dict[str, str],
    ) -> None:
        """Evaluate if call is a vulnerable SQL injection sink."""
        if not isinstance(call.func, ast.Attribute):
            return

        method = call.func.attr
        if method not in ("execute", "executemany", "executescript", "raw"):
            return

        # Extract query argument
        query_arg: ast.AST | None = None
        if call.args:
            query_arg = call.args[0]
        elif call.keywords:
            for kw in call.keywords:
                if kw.arg in ("operation", "query", "sql", "statement", "raw_query", "stmt"):
                    query_arg = kw.value
                    break

        if query_arg is None:
            return

        # Check receiver & query keyword false-positive controls
        try:
            receiver_str = ast.unparse(call.func.value).lower()
        except Exception:
            receiver_str = ""

        tokens = set(re.split(r"[._]", receiver_str))

        query_literals = extract_literal_strings(query_arg, assigned_literals)
        combined_text = " ".join(query_literals).upper()
        has_sql_keyword = any(re.search(r"\b" + kw + r"\b", combined_text) for kw in SQL_KEYWORDS)

        if has_sql_keyword:
            # Explicit SQL keyword present (e.g. SELECT, INSERT, etc.)
            pass
        elif not query_literals and bool(tokens & STRONG_DB_RECEIVERS):
            # Dynamic query variable without literal strings, passed to strong DB receiver
            pass
        else:
            # Query has literal strings without SQL keywords, or query has no literals
            # and receiver is not a strong DB receiver.
            return

        # Parameterized queries have constant query string in query_arg -> not tainted
        if not is_expr_tainted(query_arg, tainted_vars, request_names, argv_names, module_aliases):
            return

        col_offset = getattr(call, "col_offset", 0)
        call_key = (call.lineno, col_offset)
        if call_key in self._seen_sql_calls:
            return
        self._seen_sql_calls.add(call_key)

        evidence = self._format_evidence(call)
        fp = compute_fingerprint(
            rule_id="SAST001",
            file_path=self.file.rel_path,
            line_number=call.lineno,
            identity_hint=f"col:{col_offset}",
        )
        finding = Finding(
            rule_id="SAST001",
            title="Python SQL Injection",
            description=(
                "Unsanitized dynamic value formatted into SQL query string and executed by database driver."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.SAST,
            file_path=self.file.rel_path,
            line_number=call.lineno,
            evidence=evidence,
            impact=(
                "An attacker can manipulate SQL queries to bypass authentication, read or modify sensitive database records, or execute administrative operations."
            ),
            remediation=(
                "Use parameterized queries or prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of formatting strings."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/89.html",
                "https://owasp.org/www-community/attacks/SQL_Injection",
            ],
            fingerprint=fp,
            detected_by="caulk-engine",
        )
        self.sql_findings.append(finding)

    def _evaluate_shell_sink(
        self,
        call: ast.Call,
        tainted_vars: set[str],
        module_aliases: dict[str, str],
        function_aliases: dict[str, tuple[str, str]],
        request_names: set[str],
        argv_names: set[str],
    ) -> None:
        """Evaluate if call is a vulnerable command injection sink."""
        target_mod: str | None = None
        target_func: str | None = None

        if isinstance(call.func, ast.Attribute):
            target_func = call.func.attr
            if isinstance(call.func.value, ast.Name):
                target_mod = module_aliases.get(call.func.value.id, call.func.value.id)
        elif isinstance(call.func, ast.Name):
            func_name = call.func.id
            if func_name in function_aliases:
                target_mod, target_func = function_aliases[func_name]
            else:
                target_func = func_name

        if not target_func:
            return

        target = (target_mod or "", target_func)
        cmd_arg: ast.AST | None = None

        if target in ALWAYS_SHELL_SINKS:
            if call.args:
                cmd_arg = call.args[0]
            elif call.keywords:
                for kw in call.keywords:
                    if kw.arg in ("cmd", "command", "args"):
                        cmd_arg = kw.value
                        break

        elif target in SUBPROCESS_SHELL_SINKS:
            shell_true = False
            for kw in call.keywords:
                if kw.arg == "shell" and _is_truthy(kw.value):
                    shell_true = True
                    break

            if not shell_true:
                return

            if call.args:
                cmd_arg = call.args[0]
            elif call.keywords:
                for kw in call.keywords:
                    if kw.arg == "args":
                        cmd_arg = kw.value
                        break
        else:
            return

        if cmd_arg is None:
            return

        if not is_expr_tainted(cmd_arg, tainted_vars, request_names, argv_names, module_aliases):
            return

        col_offset = getattr(call, "col_offset", 0)
        call_key = (call.lineno, col_offset)
        if call_key in self._seen_shell_calls:
            return
        self._seen_shell_calls.add(call_key)

        evidence = self._format_evidence(call)
        fp = compute_fingerprint(
            rule_id="SAST002",
            file_path=self.file.rel_path,
            line_number=call.lineno,
            identity_hint=f"col:{col_offset}",
        )
        finding = Finding(
            rule_id="SAST002",
            title="Command Injection via Shell Execution",
            description=(
                "Unsanitized dynamic value passed to shell execution function (e.g. os.system, subprocess with shell=True)."
            ),
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category=FindingCategory.SAST,
            file_path=self.file.rel_path,
            line_number=call.lineno,
            evidence=evidence,
            impact=(
                "An attacker can inject arbitrary shell commands leading to complete host compromise, unauthorized file access, or lateral movement."
            ),
            remediation=(
                "Avoid shell=True and pass command arguments as a list of strings directly to subprocess.run or subprocess.Popen without invoking the shell."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/78.html",
                "https://owasp.org/www-community/attacks/Command_Injection",
            ],
            fingerprint=fp,
            detected_by="caulk-engine",
        )
        self.shell_findings.append(finding)

    def _format_evidence(self, call: ast.Call) -> str:
        """Create bounded, safe evidence snippet for finding reporting."""
        raw_snippet = ""
        try:
            unparsed = ast.unparse(call)
            raw_snippet = " ".join(unparsed.split())
        except Exception:
            pass

        if not raw_snippet:
            if 0 < call.lineno <= len(self.lines):
                end_lineno = getattr(call, "end_lineno", call.lineno) or call.lineno
                max_lines = min(end_lineno, call.lineno + 2)
                snippet_lines = [self.lines[i].strip() for i in range(call.lineno - 1, max_lines)]
                raw_snippet = " ".join(snippet_lines)
            else:
                raw_snippet = "sink_call(...)"

        if len(raw_snippet) > 120:
            raw_snippet = raw_snippet[:117] + "..."

        return sanitize_evidence(raw_snippet)


def run_sast_analysis(
    file: DiscoveredFile, context: ScanContext
) -> tuple[list[Finding], list[Finding]]:
    """Execute SAST analysis on a file, caching results in ScanContext for efficiency."""
    if file.path in context._sast_cache:
        sql, shell = context._sast_cache[file.path]
        return list(sql), list(shell)

    tree = context.get_ast(file)
    if tree is None:
        context._sast_cache[file.path] = ([], [])
        return ([], [])

    analyzer = PythonASTSecurityAnalyzer(file, context)
    sql_findings, shell_findings = analyzer.analyze(tree)
    context._sast_cache[file.path] = (list(sql_findings), list(shell_findings))
    return list(sql_findings), list(shell_findings)


class SQLInjectionRule(Rule):
    """Detects SQL queries dynamically constructed with unsanitized dynamic inputs."""

    rule_id = "SAST001"
    title = "Python SQL Injection"
    description = (
        "Unsanitized dynamic value formatted into SQL query string and executed by database driver."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SAST
    impact = "An attacker can manipulate SQL queries to bypass authentication, read or modify sensitive database records, or execute administrative operations."
    remediation = "Use parameterized queries or prepared statements (e.g. cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))) instead of formatting strings."
    references = [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ]
    file_patterns = ["*.py"]
    supported_ecosystems: list[str] = []

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        sql_findings, _ = run_sast_analysis(file, context)
        return list(sql_findings)


class ShellCommandInjectionRule(Rule):
    """Detects shell commands dynamically constructed with unsanitized inputs."""

    rule_id = "SAST002"
    title = "Command Injection via Shell Execution"
    description = "Unsanitized dynamic value passed to shell execution function (e.g. os.system, subprocess with shell=True)."
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = FindingCategory.SAST
    impact = "An attacker can inject arbitrary shell commands leading to complete host compromise, unauthorized file access, or lateral movement."
    remediation = "Avoid shell=True and pass command arguments as a list of strings directly to subprocess.run or subprocess.Popen without invoking the shell."
    references = [
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/www-community/attacks/Command_Injection",
    ]
    file_patterns = ["*.py"]
    supported_ecosystems: list[str] = []

    def scan_file(self, file: DiscoveredFile, context: ScanContext) -> list[Finding]:
        _, shell_findings = run_sast_analysis(file, context)
        return list(shell_findings)
