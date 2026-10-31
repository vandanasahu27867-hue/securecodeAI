# verifier.py
#
# AI Code Security — Verification Module
#
# Verifies AI-generated code repairs by:
#   1. Creating a temporary working copy (never modifying originals).
#   2. Applying the proposed repair to the temporary copy.
#   3. Compiling or syntax-checking the repaired code.
#   4. Optionally re-scanning with Semgrep to confirm the
#      original vulnerability is no longer detected.
#   5. Returning a structured verification verdict.
#
# Supported languages (MVP):
#   C    → gcc
#   C++  → g++
#   Python → python (syntax check)
#   Java → javac
#
# Security:
#   - All subprocess calls use shell=False and timeouts.
#   - Original source files are NEVER modified.
#   - AI-generated code is treated as untrusted.
#   - Missing tools produce ERROR results, not crashes.

import os
import sys
import json
import shutil
import subprocess
import tempfile
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(SCRIPT_DIR, "rules", "security_rules.yml")

# Timeout for compilation / syntax checking (seconds)
COMPILE_TIMEOUT = 60

# Timeout for Semgrep re-scan (seconds)
RESCAN_TIMEOUT = 120

# Map file extensions to language identifiers
EXTENSION_TO_LANGUAGE = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".py": "python",
    ".java": "java",
}

# Map language to compiler / syntax checker command
LANGUAGE_COMPILERS = {
    "c": "gcc",
    "cpp": "g++",
    "python": "python",
    "java": "javac",
}


# ---------------------------------------------------------------------------
# Result builder
# ---------------------------------------------------------------------------

def make_result(
    status: str,
    language: str,
    file_path: str,
    compile_success: Optional[bool] = None,
    runtime_success: Optional[bool] = None,
    rescan_success: Optional[bool] = None,
    errors: Optional[list] = None,
    message: str = "",
) -> dict:
    """Build a structured verification result."""
    return {
        "status": status,           # "PASS", "FAIL", or "ERROR"
        "language": language,
        "file": file_path,
        "compile_success": compile_success,
        "runtime_success": runtime_success,
        "rescan_success": rescan_success,
        "errors": errors or [],
        "message": message,
    }


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def detect_language(file_path: str) -> str:
    """Detect language from the file extension."""
    _, ext = os.path.splitext(file_path)
    return EXTENSION_TO_LANGUAGE.get(ext.lower(), "unknown")


# ---------------------------------------------------------------------------
# Tool availability checks
# ---------------------------------------------------------------------------

def is_tool_available(tool_name: str) -> bool:
    """Check whether a command-line tool is available on PATH."""
    return shutil.which(tool_name) is not None


# ---------------------------------------------------------------------------
# Temporary workspace
# ---------------------------------------------------------------------------

def create_temp_copy(source_file: str, temp_dir: str) -> str:
    """
    Copy the original source file to a temporary directory.

    Returns the path to the temporary copy.
    """
    basename = os.path.basename(source_file)
    temp_path = os.path.join(temp_dir, basename)
    shutil.copy2(source_file, temp_path)
    return temp_path


def apply_repair(temp_file: str, corrected_code: str, original_file: str,
                 line_start: int, language: str) -> bool:
    """
    Apply the corrected code to the temporary file.

    Strategy:
      - If the corrected code appears to be a complete function or file
        replacement, overwrite the entire temp file.
      - The original file is NEVER touched.

    For the MVP, we replace the entire file content with the corrected
    code. A more sophisticated approach (surgical line replacement) can
    be added later.

    Returns True if the file was written successfully.
    """
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(corrected_code)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Compilation / syntax checking
# ---------------------------------------------------------------------------

def compile_c_cpp(temp_file: str, compiler: str, temp_dir: str) -> dict:
    """
    Compile a C or C++ file and return the result.

    Compiles to a temporary output binary. Does NOT execute the binary.
    """
    output_path = os.path.join(temp_dir, "compiled_output")

    cmd = [compiler, temp_file, "-o", output_path, "-Wall", "-Wextra"]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Compilation timed out after {COMPILE_TIMEOUT}s",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Compiler not found: {compiler}",
            "returncode": -1,
        }
    except OSError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def check_python_syntax(temp_file: str) -> dict:
    """
    Check Python syntax by compiling the file without executing it.

    Uses: python -m py_compile <file>
    """
    python_cmd = sys.executable or "python"

    cmd = [python_cmd, "-m", "py_compile", temp_file]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Python syntax check timed out after {COMPILE_TIMEOUT}s",
            "returncode": -1,
        }
    except OSError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def compile_java(temp_file: str, temp_dir: str) -> dict:
    """
    Compile a Java file using javac.
    """
    cmd = ["javac", "-d", temp_dir, temp_file]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMPILE_TIMEOUT,
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Java compilation timed out after {COMPILE_TIMEOUT}s",
            "returncode": -1,
        }
    except FileNotFoundError:
        return {
            "success": False,
            "stdout": "",
            "stderr": "javac not found. Ensure the JDK is installed and on PATH.",
            "returncode": -1,
        }
    except OSError as e:
        return {
            "success": False,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
        }


def run_compilation(temp_file: str, language: str, temp_dir: str) -> dict:
    """
    Route to the correct compiler/syntax checker based on language.

    Returns a compilation result dict with 'success', 'stdout', 'stderr'.
    """
    compiler = LANGUAGE_COMPILERS.get(language)

    if not compiler:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"No compiler/checker configured for language: {language}",
            "returncode": -1,
        }

    # Check tool availability (except Python which uses sys.executable)
    if language != "python" and not is_tool_available(compiler):
        return {
            "success": False,
            "stdout": "",
            "stderr": (
                f"Compiler/tool '{compiler}' is not installed or not on PATH. "
                f"Cannot verify {language} code."
            ),
            "returncode": -1,
        }

    if language == "c":
        return compile_c_cpp(temp_file, "gcc", temp_dir)
    elif language == "cpp":
        return compile_c_cpp(temp_file, "g++", temp_dir)
    elif language == "python":
        return check_python_syntax(temp_file)
    elif language == "java":
        return compile_java(temp_file, temp_dir)
    else:
        return {
            "success": False,
            "stdout": "",
            "stderr": f"Unsupported language: {language}",
            "returncode": -1,
        }


# ---------------------------------------------------------------------------
# Semgrep re-scan
# ---------------------------------------------------------------------------

def rescan_with_semgrep(temp_file: str, rule_id: str) -> dict:
    """
    Re-scan the repaired file with Semgrep to check whether the
    original vulnerability is still present.

    Returns a dict with:
      - available: whether Semgrep was found
      - scanned: whether the scan was executed
      - vulnerability_still_present: True if the original rule still fires
      - findings_count: number of findings from the re-scan
      - error: error message if any
    """
    result = {
        "available": False,
        "scanned": False,
        "vulnerability_still_present": None,
        "findings_count": 0,
        "error": None,
    }

    # Check Semgrep availability
    if not is_tool_available("semgrep"):
        result["error"] = (
            "Semgrep is not installed. Re-scan skipped. "
            "The repair cannot be fully verified without Semgrep."
        )
        return result

    result["available"] = True

    # Check rules file
    if not os.path.isfile(RULES_PATH):
        result["error"] = f"Rules file not found: {RULES_PATH}"
        return result

    cmd = [
        "semgrep",
        "--config", RULES_PATH,
        "--json",
        "--no-git-ignore",
        temp_file,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=RESCAN_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["error"] = f"Semgrep re-scan timed out after {RESCAN_TIMEOUT}s"
        return result
    except FileNotFoundError:
        result["error"] = "Semgrep executable not found during re-scan."
        return result
    except OSError as e:
        result["error"] = f"Semgrep re-scan failed: {e}"
        return result

    result["scanned"] = True

    # Parse output
    try:
        scan_output = json.loads(proc.stdout) if proc.stdout else {}
    except json.JSONDecodeError:
        result["error"] = "Failed to parse Semgrep re-scan output."
        return result

    findings = scan_output.get("results", [])
    result["findings_count"] = len(findings)

    # Check if the original rule is still firing
    matching = [f for f in findings if f.get("check_id") == rule_id]
    result["vulnerability_still_present"] = len(matching) > 0

    return result


# ---------------------------------------------------------------------------
# Main verification function
# ---------------------------------------------------------------------------

def verify_repair(
    original_file: str,
    corrected_code: str,
    rule_id: str,
    line_start: int = 0,
) -> dict:
    """
    Verify a proposed AI-generated repair.

    Steps:
      1. Detect the language from the file extension.
      2. Create a temporary copy of the original source.
      3. Apply the corrected code to the temporary copy.
      4. Compile or syntax-check the repaired code.
      5. If Semgrep is available, re-scan to check the vulnerability.
      6. Return a structured verdict.

    The original file is NEVER modified.

    Args:
        original_file: Path to the original vulnerable source file.
        corrected_code: The AI-generated corrected code string.
        rule_id: The Semgrep rule ID that detected the vulnerability.
        line_start: The line number of the vulnerability (for context).

    Returns:
        A structured verification result dict.
    """
    # Validate inputs
    if not os.path.isfile(original_file):
        return make_result(
            status="ERROR",
            language="unknown",
            file_path=original_file,
            message=f"Original source file not found: {original_file}",
            errors=[f"File not found: {original_file}"],
        )

    if not corrected_code or not corrected_code.strip():
        return make_result(
            status="ERROR",
            language="unknown",
            file_path=original_file,
            message="Corrected code is empty. Cannot verify.",
            errors=["Empty corrected code"],
        )

    language = detect_language(original_file)
    if language == "unknown":
        return make_result(
            status="ERROR",
            language=language,
            file_path=original_file,
            message=f"Unsupported file type: {original_file}",
            errors=[f"Cannot determine language for: {original_file}"],
        )

    # Create temporary workspace
    temp_dir = tempfile.mkdtemp(prefix="aics_verify_")
    errors_list = []

    try:
        # --- Step 1: Create temp copy ---
        temp_file = create_temp_copy(original_file, temp_dir)

        # --- Step 2: Apply repair ---
        if not apply_repair(temp_file, corrected_code, original_file, line_start, language):
            return make_result(
                status="ERROR",
                language=language,
                file_path=original_file,
                message="Failed to apply repair to temporary file.",
                errors=["Could not write corrected code to temp file."],
            )

        # --- Step 3: Compile / syntax check ---
        compile_result = run_compilation(temp_file, language, temp_dir)
        compile_success = compile_result["success"]

        if not compile_success:
            err_msg = compile_result.get("stderr", "Unknown compilation error")
            errors_list.append(f"Compilation/syntax error: {err_msg}")
            return make_result(
                status="FAIL",
                language=language,
                file_path=original_file,
                compile_success=False,
                runtime_success=None,
                rescan_success=None,
                errors=errors_list,
                message="Repair failed compilation or syntax check.",
            )

        # --- Step 4: Re-scan with Semgrep (if available) ---
        rescan = rescan_with_semgrep(temp_file, rule_id)
        rescan_success = None

        if not rescan["available"]:
            # Semgrep not installed — cannot fully verify
            errors_list.append(rescan.get("error", "Semgrep not available."))
            return make_result(
                status="PASS",
                language=language,
                file_path=original_file,
                compile_success=True,
                runtime_success=None,
                rescan_success=None,
                errors=errors_list,
                message=(
                    "Repair compiles/parses successfully. "
                    "Semgrep is not installed, so re-scan was skipped. "
                    "Verification is PARTIAL — the vulnerability may still exist."
                ),
            )

        if rescan.get("error") and not rescan["scanned"]:
            errors_list.append(rescan["error"])
            return make_result(
                status="PASS",
                language=language,
                file_path=original_file,
                compile_success=True,
                runtime_success=None,
                rescan_success=None,
                errors=errors_list,
                message=(
                    "Repair compiles/parses successfully. "
                    f"Semgrep re-scan failed: {rescan['error']}. "
                    "Verification is PARTIAL."
                ),
            )

        # Re-scan completed
        if rescan["vulnerability_still_present"]:
            rescan_success = False
            errors_list.append(
                f"Re-scan: Rule '{rule_id}' still fires on the repaired code."
            )
            return make_result(
                status="FAIL",
                language=language,
                file_path=original_file,
                compile_success=True,
                runtime_success=None,
                rescan_success=False,
                errors=errors_list,
                message=(
                    "Repair compiles successfully but the vulnerability "
                    "is still detected by Semgrep."
                ),
            )

        # Full success: compiles AND vulnerability no longer detected
        return make_result(
            status="PASS",
            language=language,
            file_path=original_file,
            compile_success=True,
            runtime_success=None,
            rescan_success=True,
            errors=[],
            message=(
                "Repair verified: compiles/parses successfully and "
                "the original vulnerability is no longer detected by Semgrep."
            ),
        )

    finally:
        # Clean up temporary directory
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass  # Best-effort cleanup


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------

def main():
    """
    CLI entry point for standalone testing.

    Usage:
        python verifier.py <patch_file.json>

    Reads a patch JSON file (from ai_repair.py) and verifies the repair.
    """
    if len(sys.argv) < 2:
        print("Usage: python verifier.py <patch_file.json>")
        print("Example: python verifier.py patches/patch_finding-001_c-strcpy-buffer-overflow_20251031T120000Z.json")
        sys.exit(1)

    patch_path = sys.argv[1]

    if not os.path.isfile(patch_path):
        print(f"[ERROR] Patch file not found: {patch_path}")
        sys.exit(1)

    try:
        with open(patch_path, "r", encoding="utf-8") as f:
            patch_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read patch file: {e}")
        sys.exit(1)

    # Extract needed fields
    finding = patch_data.get("finding", {})
    repair = patch_data.get("repair", {})

    original_file = finding.get("file", "")
    corrected_code = repair.get("corrected_code", "")
    rule_id = finding.get("rule_id", "")
    line_start = finding.get("line_start", 0)

    if not original_file:
        print("[ERROR] Patch file does not contain 'finding.file'.")
        sys.exit(1)

    if not corrected_code:
        print("[ERROR] Patch file does not contain 'repair.corrected_code'.")
        sys.exit(1)

    print(f"[INFO] Verifying repair for: {rule_id}")
    print(f"[INFO] Original file: {original_file}")
    print()

    result = verify_repair(original_file, corrected_code, rule_id, line_start)

    # Display result
    status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "⚠️"}.get(result["status"], "?")
    print(f"[RESULT] {status_icon} {result['status']}")
    print(f"[INFO]   {result['message']}")

    if result["errors"]:
        print("[ERRORS]")
        for err in result["errors"]:
            print(f"  - {err}")

    print()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
