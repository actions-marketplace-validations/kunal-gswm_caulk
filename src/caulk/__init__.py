"""Caulk: Deterministic, open-source security checker for modern application repositories."""

__version__ = "0.3.0"
__author__ = "Caulk Contributors"

from caulk.models import Confidence, Finding, FindingCategory, FindingStatus, Severity
from caulk.scanner import CaulkScanner

__all__ = [
    "CaulkScanner",
    "Confidence",
    "Finding",
    "FindingCategory",
    "FindingStatus",
    "Severity",
    "__version__",
]
