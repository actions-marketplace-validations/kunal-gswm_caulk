"""JSON report generation for Caulk scan results."""

from __future__ import annotations

from pathlib import Path

from caulk.models import ScanResult


def generate_json_report(result: ScanResult, indent: int = 2) -> str:
    """Serialize scan result into deterministic JSON string."""
    return result.to_json(indent=indent)


def write_json_report(result: ScanResult, output_path: Path | str, indent: int = 2) -> None:
    """Write serialized scan result to an output file safely."""
    path = Path(output_path).resolve()
    content = generate_json_report(result, indent=indent)
    path.write_text(content, encoding="utf-8")
