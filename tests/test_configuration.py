"""Tests for configuration security rules."""

from __future__ import annotations

from pathlib import Path

from caulk.config import CaulkConfig
from caulk.discovery import DiscoveredFile, ProjectInventory
from caulk.rules.base import ScanContext
from caulk.rules.configuration import (
    DebugModeRule,
    DockerfileSecretExposureRule,
    DockerRootUserRule,
    PermissiveCORSRule,
)


def _make_context(
    tmp_path: Path, filename: str, content: str
) -> tuple[DiscoveredFile, ScanContext]:
    file_path = tmp_path / filename
    file_path.write_text(content, encoding="utf-8")
    dfile = DiscoveredFile(
        path=file_path, rel_path=filename, size_bytes=len(content.encode("utf-8"))
    )
    inv = ProjectInventory(root_path=tmp_path, files=[dfile])
    ctx = ScanContext(inventory=inv, config=CaulkConfig())
    return dfile, ctx


def test_debug_mode_django_positive(tmp_path: Path):
    rule = DebugModeRule()
    content = "SECRET_KEY = 'something'\nDEBUG = True\nALLOWED_HOSTS = ['*']\n"
    dfile, ctx = _make_context(tmp_path, "settings.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "CFG001"
    assert "DEBUG = True" in findings[0].evidence


def test_debug_mode_flask_positive(tmp_path: Path):
    rule = DebugModeRule()
    content = "app = Flask(__name__)\napp.run(host='0.0.0.0', port=5000, debug=True)\n"
    dfile, ctx = _make_context(tmp_path, "app.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "CFG001"


def test_debug_mode_negative_env_guarded(tmp_path: Path):
    rule = DebugModeRule()
    content = "DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'\n"
    dfile, ctx = _make_context(tmp_path, "settings.py", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_permissive_cors_positive(tmp_path: Path):
    rule = PermissiveCORSRule()
    content = (
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=['*'],\n"
        "    allow_credentials=True,\n"
        ")\n"
    )
    dfile, ctx = _make_context(tmp_path, "server.py", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "CFG002"


def test_permissive_cors_negative_no_credentials(tmp_path: Path):
    rule = PermissiveCORSRule()
    content = (
        "app.add_middleware(\n"
        "    CORSMiddleware,\n"
        "    allow_origins=['*'],\n"
        "    allow_credentials=False,\n"
        ")\n"
    )
    dfile, ctx = _make_context(tmp_path, "public_api.py", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_docker_root_user_positive(tmp_path: Path):
    rule = DockerRootUserRule()
    content = "FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD ['python', 'app.py']\n"
    dfile, ctx = _make_context(tmp_path, "Dockerfile", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "CFG003"


def test_docker_root_user_negative_with_user(tmp_path: Path):
    rule = DockerRootUserRule()
    content = (
        "FROM python:3.11-slim\n"
        "WORKDIR /app\n"
        "RUN useradd -u 1000 appuser\n"
        "USER appuser\n"
        "CMD ['python', 'app.py']\n"
    )
    dfile, ctx = _make_context(tmp_path, "Dockerfile", content)
    findings = rule.scan_file(dfile, ctx)
    assert len(findings) == 0


def test_dockerfile_secret_exposure_positive(tmp_path: Path):
    rule = DockerfileSecretExposureRule()
    content = "FROM ubuntu:22.04\nCOPY id_rsa /root/.ssh/id_rsa\nRUN chmod 600 /root/.ssh/id_rsa\n"
    dfile, ctx = _make_context(tmp_path, "Dockerfile", content)
    findings = rule.scan_file(dfile, ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "CFG004"
