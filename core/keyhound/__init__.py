"""Keyhound — detector de credenciais expostas em código."""

__version__ = "0.3.0"

from keyhound.models import Finding, Rule, Severity
from keyhound.scanner import scan_directory

__all__ = ["Finding", "Rule", "Severity", "scan_directory", "__version__"]