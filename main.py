# main.py
#
# AI Code Security -- Main Orchestrator & Bounded Repair Loop
#
# Complete pipeline orchestration:
#   1. Accept target source file and optional --max-attempts from CLI.
#   2. Run vulnerability scanner (scanner.py -> Semgrep).
#   3. If scan fails (e.g., Semgrep unavailable), record SCAN_FAILED report.
#   4. If scan finds 0 vulnerabilities, record CLEAN report.
#   5. For each finding, execute a bounded automated repair loop:
#        attempt = 1 .. max_attempts:
#          - call ai_repair.py to generate secure fix (with prior feedback if retry)
#          - call verifier.py to compile/syntax-check repaired code
#          - if compiles, re-scan with Semgrep (if available) to verify removal
#          - if verified -> stop loop for this finding
#          - if failed -> record failure feedback, retry if attempts remain
#   6. Aggregate all attempt details into results/final_report.json.
#   7. Print an ASCII-safe human-readable summary for terminal/PowerShell.
#
# Security & Safety Guarantees:
#   - NEVER overwrites original user source files.
#   - NEVER contains hardcoded API keys or secrets.
#   - All verification runs in temporary workspaces.
#   - No infinite loops: strictly bounded by max_attempts (default: 3).
#   - Distinguishes FULL verification from PARTIAL verification when Semgrep is unavailable.

import sys
import os
import json
import argparse
import subprocess
from datetime import datetime, timezone
from typing import Optional, Tuple, List, Dict, Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_SCRIPT = os.path.join(SCRIPT_DIR, "scanner.py")
FINDINGS_FILE = os.path.join(SCRIPT_DIR, "results", "findings.json")
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
FINAL_REPORT_FILE = os.path.join(RESULTS_DIR, "final_report.json")

# Supported source file extensions
SUPPORTED_EXTENSIONS = {
    ".c", ".cpp", ".cc", ".cxx",  # C / C++
    ".py",                         # Python
    ".java",                       # Java
}

DEFAULT_MAX_ATTEMPTS = 3
SCANNER_TIMEOUT = 180


# ---------------------------------------------------------------------------
# CLI & Input Validation
# ---------------------------------------------------------------------------

def validate_input(args: List[str]) -> Tuple[str, int]:
    """
    Validate command-line arguments using argparse.

    Checks:
      - source_file argument is provided
      - source_file exists and is a file
      - file extension is supported (.c, .cpp, .cc, .cxx, .py, .java)
      - max_attempts is a positive integer (default: 3)

    Returns:
      (absolute_source_file_path, max_attempts)
    """
    parser = argparse.ArgumentParser(
        description="AI Code Security -- Vulnerability Scanner & AI Repair Loop",
        add_help=False,
    )
    parser.add_argument("source_file", nargs="?", default=None, help="Path to source file to scan")
    parser.add_argument(
        "--max-attempts", "-m",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=f"Maximum automated repair attempts per vulnerability (default: {DEFAULT_MAX_ATTEMPTS})",
    )
    parser.add_argument("--help", "-h", action="store_true", help="Show help message and exit")

    parsed, unknown = parser.parse_known_args(args[1:])

    if parsed.help or not parsed.source_file:
        print("=" * 60)
        print("  AI CODE SECURITY")
        print("=" * 60)
        print()
        print("  Usage: python main.py <source_file> [--max-attempts N]")
        print()
        print("  Options:")
        print(f"    --max-attempts, -m N   Maximum repair attempts (default: {DEFAULT_MAX_ATTEMPTS})")
        print("    --help, -h             Show this help message")
        print()
        print("  Examples:")
        print("    python main.py test_code/vulnerable.c")
        print("    python main.py test_code/vulnerable.py --max-attempts 3")
        print("    python main.py test_code/Vulnerable.java -m 5")
        print()
        print("  Supported file types:")
        print("    C/C++  : .c, .cpp, .cc, .cxx")
        print("    Python : .py")
        print("    Java   : .java")
        print("=" * 60)
        sys.exit(0 if parsed.help else 1)

    source_file = parsed.source_file
    max_attempts = parsed.max_attempts

    if max_attempts < 1:
        print(f"[ERROR] Invalid --max-attempts value: {max_attempts}. Must be at least 1.")
        sys.exit(1)

    # Check file exists
    if not os.path.exists(source_file):
        print(f"[ERROR] Source file not found: {source_file}")
        sys.exit(1)

    if not os.path.isfile(source_file):
        print(f"[ERROR] Path is not a file: {source_file}")
        sys.exit(1)

    # Check supported extension
    _, ext = os.path.splitext(source_file)
    if ext.lower() not in SUPPORTED_EXTENSIONS:
        print(f"[ERROR] Unsupported file type: '{ext}'")
        print(f"        Supported extensions: {', '.join(sorted(SUPPORTED_EXTENSIONS))}")
        sys.exit(1)

    return os.path.abspath(source_file), max_attempts


# ---------------------------------------------------------------------------
# Scanner Execution
# ---------------------------------------------------------------------------

def run_scanner(source_file: str) -> Dict[str, Any]:
    """
    Run scanner.py as a subprocess to scan the source file.

    Returns a dict with:
      - success: bool
      - findings: list of finding dicts (empty on failure)
      - total_findings: int
      - error: error message or None
      - scanner_output: captured stdout
    """
    result = {
        "success": False,
        "findings": [],
        "total_findings": 0,
        "error": None,
        "scanner_output": "",
    }

    python_cmd = sys.executable or "python"
    cmd = [python_cmd, SCANNER_SCRIPT, source_file]

    print(f"[INFO] Running scanner: {os.path.basename(SCANNER_SCRIPT)}")
    print(f"[INFO] Target: {source_file}")
    print()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SCANNER_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["error"] = f"Scanner timed out after {SCANNER_TIMEOUT}s."
        return result
    except FileNotFoundError:
        result["error"] = "Python interpreter not found."
        return result
    except OSError as e:
        result["error"] = f"Failed to run scanner: {e}"
        return result

    result["scanner_output"] = proc.stdout

    # Print scanner output lines
    if proc.stdout:
        for line in proc.stdout.strip().split("\n"):
            print(f"  {line}")
        print()

    # Check for Semgrep-not-installed error
    combined_output = (proc.stdout or "") + (proc.stderr or "")
    if "semgrep" in combined_output.lower() and (
        "not installed" in combined_output.lower()
        or "not found" in combined_output.lower()
    ):
        result["error"] = (
            "Semgrep is not installed or not found on PATH.\n"
            "         Install it with: pip install semgrep\n"
            "         The scanner cannot run without Semgrep."
        )
        return result

    # Scanner exit code: 0 = no findings, 1 = findings found, 2+ = error
    if proc.returncode not in (0, 1):
        stderr_msg = proc.stderr.strip() if proc.stderr else "Unknown error"
        result["error"] = f"Scanner failed (exit code {proc.returncode}): {stderr_msg}"
        return result

    # Read findings from results/findings.json
    if not os.path.isfile(FINDINGS_FILE):
        result["error"] = f"Scanner did not produce findings file: {FINDINGS_FILE}"
        return result

    try:
        with open(FINDINGS_FILE, "r", encoding="utf-8") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        result["error"] = f"Failed to read scanner output: {e}"
        return result

    result["success"] = True
    result["findings"] = report.get("findings", [])
    result["total_findings"] = report.get("total_findings", len(result["findings"]))

    return result


# ---------------------------------------------------------------------------
# Bounded Repair & Verification Loop (Part 11)
# ---------------------------------------------------------------------------

def process_repairs_with_retry(findings: List[Dict[str, Any]], max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> List[Dict[str, Any]]:
    """
    Execute a bounded automated repair loop for each vulnerability finding.

    Flow per finding:
      attempt = 1 .. max_attempts:
        1. Call ai_repair.py (passing failure feedback from previous attempt if any)
        2. If AI repair fails to generate code, record failure. If missing API config, abort retry.
        3. Call verifier.py to compile/syntax-check repaired code in isolated workspace.
        4. Re-scan with Semgrep (if available) to verify vulnerability removal.
        5. If verified -> stop loop (PASS).
        6. If verification fails -> extract error feedback and proceed to next attempt.

    Returns:
      List of finding outcome dicts with full attempt history.
    """
    import ai_repair
    import verifier

    finding_results = []

    for i, finding in enumerate(findings):
        finding_id = finding.get("id", f"finding-{i+1:03d}")
        rule_id = finding.get("rule_id", "unknown")
        severity = finding.get("severity", "UNKNOWN")
        source_file = finding.get("file", "")
        line_start = finding.get("line_start", 0)

        print(f"  [{finding_id}] Processing: {rule_id} ({severity}) at line {line_start}")

        attempts = []
        feedback = ""
        final_status = "REPAIR_FAILED"
        best_repair = None
        best_verification = None

        for attempt in range(1, max_attempts + 1):
            print(f"    Attempt {attempt}/{max_attempts}:")
            print(f"      [1] Generating AI repair...")

            # 1. AI Repair Generation
            try:
                repair_res = ai_repair.repair_finding(finding, feedback=feedback, attempt=attempt)
            except Exception as e:
                repair_res = {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "attempt": attempt,
                    "status": "ERROR",
                    "patch_file": None,
                    "repair": None,
                    "error": f"Unexpected error during repair: {e}",
                }

            repair_status = repair_res.get("status", "ERROR")

            if repair_status != "GENERATED":
                error_msg = repair_res.get("error", "Repair generation failed.")
                print(f"          -> AI Repair failed: {error_msg}")
                attempts.append({
                    "attempt": attempt,
                    "repair_status": repair_status,
                    "repair_error": error_msg,
                    "patch_file": None,
                    "verification_status": "SKIPPED",
                    "verification_type": "SKIPPED",
                    "verification_details": {},
                    "outcome": "FAILED",
                })

                # If missing API key / model or file missing, further retries will fail identically
                if "ANTHROPIC_API_KEY" in error_msg or "ANTHROPIC_MODEL" in error_msg or "not found" in error_msg:
                    print(f"          -> Aborting repair loop: missing configuration or environment error.")
                    final_status = "REPAIR_ERROR"
                    break

                feedback = f"AI repair failed to generate code: {error_msg}"
                continue

            patch_file = repair_res.get("patch_file")
            print(f"          -> Repair generated: {os.path.basename(patch_file) if patch_file else 'saved'}")
            best_repair = repair_res

            # 2. Extract corrected code
            corrected_code = ""
            if repair_res.get("repair"):
                corrected_code = repair_res["repair"].get("corrected_code", "")

            if not corrected_code:
                print(f"          -> Verification skipped: corrected code section is empty.")
                attempts.append({
                    "attempt": attempt,
                    "repair_status": repair_status,
                    "repair_error": None,
                    "patch_file": patch_file,
                    "verification_status": "ERROR",
                    "verification_type": "ERROR",
                    "verification_details": {"message": "Empty corrected code"},
                    "outcome": "FAILED",
                })
                feedback = "Generated code block was empty. Provide full corrected code in CORRECTED_CODE section."
                continue

            # 3. Verification
            print(f"      [2] Verifying repair in temporary workspace...")
            try:
                verify_res = verifier.verify_repair(source_file, corrected_code, rule_id, line_start)
            except Exception as e:
                verify_res = {
                    "status": "ERROR",
                    "message": f"Unexpected error during verification: {e}",
                    "errors": [str(e)],
                }

            best_verification = verify_res
            v_status = verify_res.get("status", "ERROR")
            v_message = verify_res.get("message", "")
            rescan_success = verify_res.get("rescan_success")

            # Determine verification type
            if v_status == "PASS":
                if rescan_success is True:
                    v_type = "FULL"
                elif rescan_success is None:
                    v_type = "PARTIAL"
                else:
                    v_type = "UNKNOWN"
            else:
                v_type = v_status

            print(f"          -> Verification: {v_status} ({v_type})")

            attempts.append({
                "attempt": attempt,
                "repair_status": repair_status,
                "repair_error": None,
                "patch_file": patch_file,
                "verification_status": v_status,
                "verification_type": v_type,
                "verification_details": verify_res,
                "outcome": "SUCCESS" if v_status == "PASS" else "FAILED",
            })

            # Check if verification succeeded
            if v_status == "PASS":
                if v_type == "FULL":
                    final_status = "REPAIRED"
                    print(f"          -> Vulnerability fully verified and fixed on attempt {attempt} [OK]")
                else:
                    final_status = "REPAIRED_PARTIAL"
                    print(f"          -> Code compiles/parses, but Semgrep re-scan was skipped (PARTIAL verification) [WARN]")
                break
            else:
                # Verification failed: format feedback for next attempt
                err_details = "; ".join(verify_res.get("errors", [])) or v_message
                feedback = f"Attempt {attempt} failed verification: {err_details}"
                print(f"          -> Attempt {attempt} failed verification. Feedback captured for retry.")

        # Final status check for finding
        if final_status not in ("REPAIRED", "REPAIRED_PARTIAL", "REPAIR_ERROR"):
            final_status = "REPAIR_FAILED"
            print(f"  [{finding_id}] Maximum attempts ({max_attempts}) reached without successful repair.")

        finding_results.append({
            "finding": finding,
            "final_status": final_status,
            "total_attempts": len(attempts),
            "attempts": attempts,
            "best_repair": best_repair,
            "best_verification": best_verification,
        })
        print()

    return finding_results


# ---------------------------------------------------------------------------
# Report Generation (Part 12)
# ---------------------------------------------------------------------------

def generate_final_report(
    source_file: str,
    scan_result: Dict[str, Any],
    repair_results: List[Dict[str, Any]],
    max_attempts: int,
) -> Dict[str, Any]:
    """
    Generate the final comprehensive report aggregating scan, repair attempts,
    verification verdicts, and overall security status.
    """
    total_findings = scan_result.get("total_findings", 0)
    scan_success = scan_result.get("success", False)

    repaired_full = 0
    repaired_partial = 0
    repair_failed = 0
    repair_error = 0
    total_attempts_made = 0

    detailed_results = []
    limitations = []

    # Check for known system limitations
    if not scan_success and scan_result.get("error"):
        if "semgrep" in scan_result["error"].lower():
            limitations.append(
                "Semgrep scanner is not installed or unavailable on this system. "
                "Static vulnerability scanning and re-scan verification could not be executed."
            )

    for entry in repair_results:
        finding = entry["finding"]
        final_status = entry["final_status"]
        attempts = entry["attempts"]
        total_attempts_made += len(attempts)

        if final_status == "REPAIRED":
            repaired_full += 1
        elif final_status == "REPAIRED_PARTIAL":
            repaired_partial += 1
        elif final_status == "REPAIR_ERROR":
            repair_error += 1
        else:
            repair_failed += 1

        # Check if any attempt had partial verification
        for att in attempts:
            if att.get("verification_type") == "PARTIAL":
                part_msg = "Semgrep was unavailable during verification re-scan; verification is partial."
                if part_msg not in limitations:
                    limitations.append(part_msg)

        detailed_results.append({
            "finding_id": finding.get("id"),
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "vulnerability_type": finding.get("vulnerability_type"),
            "file": finding.get("file"),
            "line": finding.get("line_start"),
            "code": finding.get("code"),
            "message": finding.get("message"),
            "final_status": final_status,
            "total_attempts": entry["total_attempts"],
            "attempts": attempts,
        })

    # Determine overall status according to Part 12 specs:
    # CLEAN, VULNERABILITIES_FOUND, REPAIRED, REPAIRED_PARTIAL, REPAIR_FAILED, SCAN_FAILED
    if not scan_success:
        overall_status = "SCAN_FAILED"
    elif total_findings == 0:
        overall_status = "CLEAN"
    elif repaired_full == total_findings:
        overall_status = "REPAIRED"
    elif (repaired_full + repaired_partial) == total_findings:
        overall_status = "REPAIRED_PARTIAL"
    elif repaired_full > 0 or repaired_partial > 0:
        overall_status = "REPAIR_FAILED"
    elif repair_error == total_findings:
        overall_status = "VULNERABILITIES_FOUND"
    else:
        overall_status = "REPAIR_FAILED"

    report = {
        "report_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": "AI Code Security",
            "version": "1.0.0",
            "max_repair_attempts": max_attempts,
        },
        "input_file": source_file,
        "scan": {
            "status": "SUCCESS" if scan_success else "FAILED",
            "total_findings": total_findings,
            "error": scan_result.get("error"),
        },
        "findings": scan_result.get("findings", []),
        "repair_summary": {
            "total_findings": total_findings,
            "repaired_full": repaired_full,
            "repaired_partial": repaired_partial,
            "repair_failed": repair_failed,
            "repair_error": repair_error,
            "total_attempts_made": total_attempts_made,
        },
        "verification_summary": {
            "pass_full": repaired_full,
            "pass_partial": repaired_partial,
            "fail": repair_failed,
            "error_or_skipped": repair_error,
        },
        "overall_status": overall_status,
        "limitations": limitations,
        "detailed_results": detailed_results,
    }

    return report


def save_final_report(report: Dict[str, Any]) -> str:
    """Save the final report to results/final_report.json."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    try:
        with open(FINAL_REPORT_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        return FINAL_REPORT_FILE
    except OSError as e:
        print(f"[ERROR] Failed to save final report: {e}")
        return ""


# ---------------------------------------------------------------------------
# ASCII-Safe Terminal Summary (Part 12)
# ---------------------------------------------------------------------------

def print_summary(report: Dict[str, Any]):
    """
    Print an ASCII-safe human-readable summary of the pipeline execution.
    Ensures Windows PowerShell / cp1252 consoles will never crash.
    """
    scan = report["scan"]
    repair = report["repair_summary"]
    verify = report["verification_summary"]
    status = report["overall_status"]

    print()
    print("=" * 60)
    print("  AI CODE SECURITY -- PIPELINE SUMMARY")
    print("=" * 60)
    print(f"  File:         {report['input_file']}")
    print(f"  Timestamp:    {report['report_metadata']['timestamp']}")
    print(f"  Max Attempts: {report['report_metadata']['max_repair_attempts']}")
    print("-" * 60)

    # Scan Section
    print()
    print("  SCAN RESULTS:")
    print(f"    Status:   {scan['status']}")
    print(f"    Findings: {scan['total_findings']}")
    if scan.get("error"):
        print(f"    Error:    {scan['error']}")

    # Repair & Verification Summary
    if scan["total_findings"] > 0:
        print()
        print("  AUTOMATED REPAIR SUMMARY:")
        print(f"    Total Vulnerabilities:  {repair['total_findings']}")
        print(f"    Repaired (Full):        {repair['repaired_full']}")
        print(f"    Repaired (Partial):     {repair['repaired_partial']}")
        print(f"    Failed:                 {repair['repair_failed']}")
        if repair["repair_error"] > 0:
            print(f"    Errors (No AI repair):  {repair['repair_error']}")
        print(f"    Total Attempts Made:    {repair['total_attempts_made']}")

        print()
        print("  VERIFICATION SUMMARY:")
        print(f"    Pass (Full Re-scan):    {verify['pass_full']}")
        print(f"    Pass (Partial):         {verify['pass_partial']}")
        print(f"    Fail:                   {verify['fail']}")
        if verify["error_or_skipped"] > 0:
            print(f"    Skipped / Error:        {verify['error_or_skipped']}")

    # Overall Status Badge
    print()
    print("-" * 60)
    status_text = {
        "CLEAN": "No vulnerabilities detected in source code.",
        "REPAIRED": "All vulnerabilities repaired and fully verified with Semgrep.",
        "REPAIRED_PARTIAL": "All repairs compile/pass syntax check; re-scan skipped (Semgrep unavailable).",
        "REPAIR_FAILED": "One or more vulnerabilities could not be successfully repaired.",
        "VULNERABILITIES_FOUND": "Vulnerabilities detected; AI repairs were not generated.",
        "SCAN_FAILED": "Vulnerability scan failed. Cannot determine security status.",
    }.get(status, status)

    status_badge = {
        "CLEAN": "[OK]",
        "REPAIRED": "[OK]",
        "REPAIRED_PARTIAL": "[WARN]",
        "REPAIR_FAILED": "[FAIL]",
        "VULNERABILITIES_FOUND": "[WARN]",
        "SCAN_FAILED": "[FAIL]",
    }.get(status, "[?]")

    print(f"  OVERALL STATUS: {status_badge} {status}")
    print(f"  DETAILS:        {status_text}")
    print("=" * 60)

    # Limitations
    if report.get("limitations"):
        print()
        print("  LIMITATIONS & NOTES:")
        for lim in report["limitations"]:
            print(f"    - {lim}")

    # Detailed findings attempt table
    details = report.get("detailed_results", [])
    if details:
        print()
        print("  PER-VULNERABILITY ATTEMPT DETAILS:")
        print()
        for d in details:
            sev = d.get("severity", "?")
            badge = "[!!]" if sev == "CRITICAL" else "[!]" if sev == "HIGH" else "[.]"
            print(f"    {badge} [{d.get('finding_id', '?')}] {d.get('rule_id', '?')}")
            print(f"       Type:         {d.get('vulnerability_type', '?')}")
            print(f"       Location:     {d.get('file', '?')}:{d.get('line', '?')}")
            print(f"       Final Status: {d.get('final_status', '?')}")
            print(f"       Attempts:     {d.get('total_attempts', 0)}")

            for att in d.get("attempts", []):
                att_num = att.get("attempt")
                r_stat = att.get("repair_status")
                v_stat = att.get("verification_status")
                v_type = att.get("verification_type")
                out = att.get("outcome")
                print(f"         Attempt {att_num}: AI={r_stat} | Verify={v_stat} ({v_type}) | Outcome={out}")
                if att.get("repair_error"):
                    print(f"           Error: {att['repair_error']}")
            print()


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main():
    """Main orchestrator entry point."""
    source_file, max_attempts = validate_input(sys.argv)

    print("=" * 60)
    print("  AI CODE SECURITY -- SCAN & REPAIR PIPELINE")
    print("=" * 60)
    print(f"  Target:       {source_file}")
    print(f"  Max Attempts: {max_attempts}")
    print("=" * 60)
    print()

    # Step 1: Scanner Execution
    print("[STEP 1/3] Scanning for vulnerabilities...")
    print("-" * 60)
    scan_result = run_scanner(source_file)

    # Handle scan failure
    if not scan_result["success"]:
        print(f"[ERROR] Scan failed: {scan_result['error']}")
        print()
        print("[INFO] Pipeline halted: cannot proceed to repair without successful scan.")
        print("[INFO] No vulnerabilities were fabricated. No repairs attempted.")

        report = generate_final_report(source_file, scan_result, [], max_attempts)
        report_path = save_final_report(report)
        if report_path:
            print(f"[INFO] Report saved to: {report_path}")
        print_summary(report)
        sys.exit(1)

    total_findings = scan_result["total_findings"]
    print(f"[INFO] Scan complete. {total_findings} finding(s) detected.")
    print()

    # Step 2: Handle Zero Findings (Clean)
    if total_findings == 0:
        print("[INFO] No vulnerabilities detected. Code is CLEAN.")
        report = generate_final_report(source_file, scan_result, [], max_attempts)
        report_path = save_final_report(report)
        if report_path:
            print(f"[INFO] Report saved to: {report_path}")
        print_summary(report)
        sys.exit(0)

    # Step 3: Bounded Automated Repair Loop
    print(f"[STEP 2/3] Executing automated repair loop (max {max_attempts} attempts/finding)...")
    print("-" * 60)
    repair_results = process_repairs_with_retry(scan_result["findings"], max_attempts=max_attempts)
    print()

    # Step 4: Generate & Save Final Report
    print("[STEP 3/3] Generating final report...")
    print("-" * 60)
    report = generate_final_report(source_file, scan_result, repair_results, max_attempts)
    report_path = save_final_report(report)
    if report_path:
        print(f"[INFO] Final report saved to: {report_path}")

    # Step 5: Terminal Output
    print_summary(report)

    # Return exit code: 0 if CLEAN or REPAIRED or REPAIRED_PARTIAL, 1 otherwise
    if report["overall_status"] in ("CLEAN", "REPAIRED", "REPAIRED_PARTIAL"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
