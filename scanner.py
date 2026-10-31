# scanner.py
#
# AI Code Security — Vulnerability Scanner Module
#
# Scans C/C++ source files for dangerous security patterns using
# Semgrep with custom rules. Produces structured JSON findings.
#
# Usage:
#   python scanner.py <path_to_c_file>
#
# Example:
#   python scanner.py test_code/vulnerable.c
#
# Output:
#   results/findings.json
#
# MVP target vulnerabilities:
#   1. strcpy()  — Buffer Overflow        — HIGH
#   2. gets()    — Unsafe Input / Overflow — CRITICAL
#   3. sprintf() — Buffer Overflow        — HIGH

import sys
import os
import json
import subprocess
import shutil
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Path to our custom Semgrep rules (relative to this script's directory)
RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "security_rules.yml")

# Output directory and file (relative to this script's directory)
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
FINDINGS_FILE = os.path.join(RESULTS_DIR, "findings.json")

# Severity mapping: Semgrep severity → our project severity
SEVERITY_MAP = {
    "ERROR": "CRITICAL",
    "WARNING": "HIGH",
    "INFO": "LOW",
}

# Timeout for the Semgrep subprocess (seconds)
SEMGREP_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def validate_source_file(file_path):
    """Validate that the provided source file exists and is a file."""
    if not os.path.exists(file_path):
        print(f"[ERROR] Source file not found: {file_path}")
        sys.exit(1)

    if not os.path.isfile(file_path):
        print(f"[ERROR] Path is not a file: {file_path}")
        sys.exit(1)

    return os.path.abspath(file_path)


def validate_rules_file():
    """Validate that the Semgrep rules file exists."""
    if not os.path.exists(RULES_PATH):
        print(f"[ERROR] Semgrep rules file not found: {RULES_PATH}")
        print("        Expected at: rules/security_rules.yml")
        sys.exit(1)

    return RULES_PATH


def check_semgrep_installed():
    """Check that Semgrep is available on the system PATH."""
    if shutil.which("semgrep") is None:
        print("[ERROR] Semgrep is not installed or not found on PATH.")
        print("        Install it with: pip install semgrep")
        print("        Then try running the scanner again.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Semgrep execution
# ---------------------------------------------------------------------------

def run_semgrep(source_file, rules_file):
    """
    Execute Semgrep with our custom rules against the source file.

    Returns the parsed JSON output from Semgrep, or None on failure.

    Command executed (as argument list, NOT through a shell):
        semgrep --config <rules_file> --json --no-git-ignore <source_file>
    """
    cmd = [
        "semgrep",
        "--config", rules_file,
        "--json",
        "--no-git-ignore",
        source_file,
    ]

    print(f"[INFO] Running Semgrep scan...")
    print(f"[INFO] Command: {' '.join(cmd)}")
    print(f"[INFO] Target:  {source_file}")
    print(f"[INFO] Rules:   {rules_file}")
    print()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SEMGREP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Semgrep timed out after {SEMGREP_TIMEOUT} seconds.")
        sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] Semgrep executable not found.")
        print("        Install it with: pip install semgrep")
        sys.exit(1)
    except OSError as e:
        print(f"[ERROR] Failed to execute Semgrep: {e}")
        sys.exit(1)

    # Semgrep can return non-zero exit codes for findings (exit code 1)
    # or for errors (exit code 2+). We try to parse JSON regardless,
    # but report stderr if present.
    if result.stderr and result.stderr.strip():
        # Print stderr as informational — Semgrep often writes
        # progress/version info to stderr even on success.
        for line in result.stderr.strip().split("\n"):
            print(f"[SEMGREP STDERR] {line}")
        print()

    # Parse JSON output
    if not result.stdout or not result.stdout.strip():
        print("[ERROR] Semgrep produced no output.")
        if result.returncode != 0:
            print(f"[ERROR] Semgrep exited with code {result.returncode}.")
        sys.exit(1)

    try:
        semgrep_output = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Failed to parse Semgrep JSON output: {e}")
        print(f"[ERROR] Raw output (first 500 chars): {result.stdout[:500]}")
        sys.exit(1)

    # Check for Semgrep-level errors in the JSON response
    if "errors" in semgrep_output and semgrep_output["errors"]:
        print("[WARNING] Semgrep reported errors:")
        for err in semgrep_output["errors"]:
            msg = err.get("message", err.get("long_msg", str(err)))
            print(f"  - {msg}")
        print()

    return semgrep_output


# ---------------------------------------------------------------------------
# Finding extraction and severity mapping
# ---------------------------------------------------------------------------

def extract_findings(semgrep_output, source_file):
    """
    Extract and structure vulnerability findings from Semgrep's JSON output.

    Each finding includes:
      - rule_id: which rule matched
      - severity: our severity label (CRITICAL / HIGH)
      - vulnerability_type: category of vulnerability
      - file: path to the source file
      - line_start / line_end: location in the file
      - column_start / column_end: column range
      - message: human-readable explanation
      - cwe: list of CWE identifiers
      - code: the matched source code snippet
      - fix_hint: suggested fix from rule metadata
    """
    raw_results = semgrep_output.get("results", [])
    findings = []

    for i, result in enumerate(raw_results):
        # --- Core fields ---
        rule_id = result.get("check_id", "unknown-rule")

        # --- Location ---
        file_path = result.get("path", source_file)
        start = result.get("start", {})
        end = result.get("end", {})
        line_start = start.get("line", 0)
        line_end = end.get("line", line_start)
        col_start = start.get("col", 0)
        col_end = end.get("col", 0)

        # --- Extra fields (message, severity, metadata, code) ---
        extra = result.get("extra", {})
        message = extra.get("message", "No description available.")
        semgrep_severity = extra.get("severity", "WARNING")

        # --- Metadata from our custom rules ---
        metadata = extra.get("metadata", {})
        severity_label = metadata.get("severity_label", SEVERITY_MAP.get(semgrep_severity, "UNKNOWN"))
        vulnerability_type = metadata.get("vulnerability_type", "Unknown")
        cwe_list = metadata.get("cwe", [])
        fix_hint = metadata.get("fix_hint", "")
        references = metadata.get("references", [])

        # --- Matched source code ---
        matched_code = extra.get("lines", "").strip()

        # --- Build structured finding ---
        finding = {
            "id": f"finding-{i + 1:03d}",
            "rule_id": rule_id,
            "severity": severity_label,
            "vulnerability_type": vulnerability_type,
            "file": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "column_start": col_start,
            "column_end": col_end,
            "message": message,
            "cwe": cwe_list,
            "code": matched_code,
            "fix_hint": fix_hint,
            "references": references,
        }

        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_report(source_file, findings):
    """
    Build the final structured JSON report.
    """
    # Count findings by severity
    severity_counts = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner_version": "1.0.0",
            "rules_file": RULES_PATH,
        },
        "scan_target": source_file,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
    }

    return report


def save_report(report):
    """
    Save the report to results/findings.json.
    Creates the results/ directory if it does not exist.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)

    try:
        with open(FINDINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[INFO] Report saved to: {FINDINGS_FILE}")
    except OSError as e:
        print(f"[ERROR] Failed to save report: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------

def print_summary(report):
    """Print a human-readable summary of the scan results to the console."""
    findings = report["findings"]
    total = report["total_findings"]

    print("=" * 60)
    print("  AI CODE SECURITY — SCAN RESULTS")
    print("=" * 60)
    print(f"  Target: {report['scan_target']}")
    print(f"  Total findings: {total}")

    if report["severity_summary"]:
        print(f"  Severity breakdown: ", end="")
        parts = [f"{sev}: {count}" for sev, count in report["severity_summary"].items()]
        print(", ".join(parts))
    print("=" * 60)

    if total == 0:
        print("  No vulnerabilities found. [OK]")
        print("=" * 60)
        return

    for finding in findings:
        sev = finding["severity"]
        icon = "[!!]" if sev == "CRITICAL" else "[!]" if sev == "HIGH" else "[.]"
        print(f"\n  {icon} [{finding['id']}] {finding['rule_id']}")
        print(f"     Severity: {sev}")
        print(f"     Type:     {finding['vulnerability_type']}")
        print(f"     File:     {finding['file']}:{finding['line_start']}")
        print(f"     Code:     {finding['code']}")
        if finding["cwe"]:
            print(f"     CWE:      {', '.join(finding['cwe'])}")

    print()
    print("=" * 60)
    print(f"  Scan complete. {total} finding(s) written to:")
    print(f"  {FINDINGS_FILE}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Main entry point for the scanner module."""
    # --- Parse CLI arguments ---
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <path_to_c_file>")
        print("Example: python scanner.py test_code/vulnerable.c")
        sys.exit(1)

    source_file = sys.argv[1]

    # --- Validate inputs ---
    source_file = validate_source_file(source_file)
    rules_file = validate_rules_file()
    check_semgrep_installed()

    # --- Run Semgrep ---
    semgrep_output = run_semgrep(source_file, rules_file)

    # --- Extract findings ---
    findings = extract_findings(semgrep_output, source_file)

    # --- Generate report ---
    report = generate_report(source_file, findings)

    # --- Save report ---
    save_report(report)

    # --- Display summary ---
    print_summary(report)

    # --- Exit code: 0 if no findings, 1 if findings found ---
    # (This lets CI/CD pipelines treat findings as a failure)
    sys.exit(0 if len(findings) == 0 else 1)


if __name__ == "__main__":
    main()
