"""
=============================================================================
SecureCode AI - MCP FastMCP Security Server (mcp_server/security_server.py)
=============================================================================
Genuine Model Context Protocol (MCP) server implementation using FastMCP.
Exposes 5 specialized security tools for AI security agents:
  1. scan_code
  2. analyze_vulnerability
  3. lookup_cve
  4. suggest_secure_patch
  5. generate_security_report
=============================================================================
"""

import sys
import os

# Add root and MCP directories to path for imports
MCP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_DIR = os.path.dirname(MCP_DIR)
for path in (BASE_DIR, MCP_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

try:
    import backend
except ImportError:
    import BACKEND as backend
    sys.modules["backend"] = backend

from mcp.server.fastmcp import FastMCP
from backend.scanner import scan_source_code
from backend.security_analyzer import (
    analyze_vulnerability_details,
    query_cve_intelligence,
    synthesize_secure_patch
)
from backend.report_generator import generate_json_report, generate_pdf_report

# Initialize the FastMCP Security Server
mcp = FastMCP("SecureCode-AI-Security-Agent")


@mcp.tool()
def scan_code(code: str, language: str = "python") -> dict:
    """
    TOOL 1: Run static security scanners (Bandit for Python, AST/Regex pattern rules)
    on source code to identify security vulnerabilities.

    Parameters:
      code: The raw source code string to scan.
      language: Programming language (python, java, c, cpp, javascript).

    Returns:
      Structured JSON containing health score, vulnerability count, severity distribution,
      and detailed findings list with line numbers, CWE, and fix hints.
    """
    if not code or not code.strip():
        return {
            "status": "error",
            "message": "Source code cannot be empty.",
            "findings": []
        }
    return scan_source_code(code, language)


@mcp.tool()
def analyze_vulnerability(
    vulnerability_type: str,
    code_snippet: str = "",
    language: str = "python"
) -> dict:
    """
    TOOL 2: Analyze detected security issues to explain root causes, potential impact,
    and remediation recommendations.

    Parameters:
      vulnerability_type: Name or category of vulnerability (e.g. 'SQL Injection', 'CWE-78').
      code_snippet: The vulnerable code snippet for context.
      language: Source code language.

    Returns:
      Analysis report with root cause, impact severity, CVSS 3.1 estimate, and remediation.
    """
    return analyze_vulnerability_details(vulnerability_type, code_snippet, language)


@mcp.tool()
def lookup_cve(
    vulnerability_type: str,
    package_or_cwe: str = ""
) -> dict:
    """
    TOOL 3: Search relevant vulnerability intelligence and OSV API database.

    Parameters:
      vulnerability_type: Vulnerability name or keyword (e.g. 'Command Injection').
      package_or_cwe: Package name (e.g. 'requests', 'flask') or CWE ID (e.g. 'CWE-89').

    Returns:
      Verified CVE/GHSA IDs, vulnerability summaries, published dates, and advisory URLs.
    """
    return query_cve_intelligence(vulnerability_type, package_or_cwe)


@mcp.tool()
def suggest_secure_patch(
    code: str,
    vulnerability_details: str = "",
    language: str = "python"
) -> dict:
    """
    TOOL 4: Generate a context-aware secure replacement patch suggestion with unified diff.
    NOTE: Never automatically modifies the original file; requires explicit user approval.

    Parameters:
      code: The vulnerable source code.
      vulnerability_details: Description or CWE of the target issue to fix.
      language: Source code language.

    Returns:
      Suggested patched code, explanation of security modifications, unified diff,
      and user approval flag.
    """
    return synthesize_secure_patch(code, vulnerability_details, language)


@mcp.tool()
def generate_security_report(
    findings: list,
    summary: dict,
    format: str = "json"
) -> dict:
    """
    TOOL 5: Generate a structured security report in JSON or PDF format.

    Parameters:
      findings: List of detected vulnerability finding dicts.
      summary: Scan summary metrics (score, total, severity counts).
      format: Desired export format ('json' or 'pdf').

    Returns:
      Metadata containing report ID, saved file path, and status.
    """
    fmt = format.lower().strip()
    if fmt == "pdf":
        _, file_path = generate_pdf_report(findings, summary)
    else:
        _, file_path = generate_json_report(findings, summary)

    return {
        "status": "success",
        "format": fmt,
        "file_path": file_path,
        "filename": os.path.basename(file_path),
        "total_findings": len(findings)
    }


if __name__ == "__main__":
    # When run directly, start the FastMCP STDIO server
    mcp.run()
