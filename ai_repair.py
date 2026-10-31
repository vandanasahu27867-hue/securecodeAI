# ai_repair.py
#
# AI Code Security — AI Repair Module
#
# Takes a vulnerability finding produced by scanner.py, gathers
# relevant source-code context, builds a repair prompt, and calls
# the Anthropic Claude API to generate a proposed secure fix.
#
# The proposed fix is saved to patches/ and is treated as UNTRUSTED
# until verified by verifier.py.
#
# Configuration (from environment variables):
#   ANTHROPIC_API_KEY  — required, must be set before use
#   ANTHROPIC_MODEL    — required, must be set before use
#
# This module does NOT:
#   - overwrite original source files
#   - execute AI-generated code
#   - claim that a repair is correct
#   - hardcode any API key or model name

import os
import sys
import json
import re
from datetime import datetime, timezone
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Directory for saving generated patches (relative to this script)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PATCHES_DIR = os.path.join(SCRIPT_DIR, "patches")

# Number of lines of surrounding context to include in the prompt
CONTEXT_LINES_BEFORE = 10
CONTEXT_LINES_AFTER = 10


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------

def load_api_config() -> dict:
    """
    Load and validate Anthropic API configuration from environment variables.

    Returns a dict with 'api_key' and 'model'.
    Raises EnvironmentError if either variable is missing or empty.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    model = os.environ.get("ANTHROPIC_MODEL", "").strip()

    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY is not set. "
            "Please set it in your environment or .env file.\n"
            "Example: export ANTHROPIC_API_KEY=sk-ant-..."
        )

    if not model:
        raise EnvironmentError(
            "ANTHROPIC_MODEL is not set. "
            "Please set it in your environment or .env file.\n"
            "Example: export ANTHROPIC_MODEL=claude-sonnet-4-20250514"
        )

    return {"api_key": api_key, "model": model}


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

# Map file extensions to language names used in prompts
EXTENSION_TO_LANGUAGE = {
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".cxx": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".py": "Python",
    ".java": "Java",
}


def detect_language(file_path: str) -> str:
    """Detect the programming language from the file extension."""
    _, ext = os.path.splitext(file_path)
    return EXTENSION_TO_LANGUAGE.get(ext.lower(), "Unknown")


# ---------------------------------------------------------------------------
# Source-code context extraction
# ---------------------------------------------------------------------------

def read_source_context(
    file_path: str,
    line_start: int,
    lines_before: int = CONTEXT_LINES_BEFORE,
    lines_after: int = CONTEXT_LINES_AFTER,
) -> dict:
    """
    Read source code around the vulnerability location.

    Returns a dict containing:
      - full_source: the entire file contents
      - context_lines: the surrounding code with line numbers
      - vulnerable_line: the specific vulnerable line
      - context_start: first line number in the context
      - context_end: last line number in the context
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()

    total_lines = len(all_lines)

    # Calculate context range (1-indexed)
    ctx_start = max(1, line_start - lines_before)
    ctx_end = min(total_lines, line_start + lines_after)

    # Extract context lines with line numbers
    context_lines = []
    for i in range(ctx_start - 1, ctx_end):
        line_num = i + 1
        marker = " >>>" if line_num == line_start else "    "
        context_lines.append(f"{marker} {line_num:4d} | {all_lines[i].rstrip()}")

    # The vulnerable line itself
    vuln_line = ""
    if 1 <= line_start <= total_lines:
        vuln_line = all_lines[line_start - 1].rstrip()

    return {
        "full_source": "".join(all_lines),
        "context_lines": "\n".join(context_lines),
        "vulnerable_line": vuln_line,
        "context_start": ctx_start,
        "context_end": ctx_end,
        "total_lines": total_lines,
    }


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def build_repair_prompt(
    finding: dict,
    source_context: dict,
    language: str,
    feedback: str = "",
    attempt: int = 1,
) -> str:
    """
    Build a structured prompt for Claude to generate a secure repair.

    The prompt includes:
      - programming language
      - vulnerability type, severity, and rule ID
      - the vulnerable code with surrounding context
      - the scanner's message explaining the issue
      - the fix hint from the Semgrep rule metadata
      - feedback from previous failed attempts (if any)
      - a clear request for a repair
    """
    rule_id = finding.get("rule_id", "unknown")
    severity = finding.get("severity", "UNKNOWN")
    vuln_type = finding.get("vulnerability_type", "Unknown")
    message = finding.get("message", "No description available.")
    fix_hint = finding.get("fix_hint", "")
    code_snippet = finding.get("code", "")
    line_start = finding.get("line_start", 0)

    prompt = f"""You are a senior software security engineer. A static analysis tool has detected a security vulnerability in {language} source code.

## Vulnerability Details

- **Rule ID**: {rule_id}
- **Vulnerability Type**: {vuln_type}
- **Severity**: {severity}
- **Location**: Line {line_start}
- **Language**: {language}

## Scanner Message

{message}

## Vulnerable Code (with context)

The line marked with >>> is the vulnerable line.

```
{source_context["context_lines"]}
```

## Matched Code Snippet

```{language.lower()}
{code_snippet}
```
"""

    if fix_hint:
        prompt += f"""
## Fix Hint from Scanner

{fix_hint}
"""

    if feedback:
        prompt += f"""
## Verification Failure Feedback (Attempt {attempt - 1})

The previous repair attempt was tested and failed with the following details:
{feedback}

Please carefully address this failure in your new repair.
"""

    prompt += f"""
## Your Task

1. **Explain** the vulnerability clearly in 2-3 sentences.
2. **Provide the corrected code** that fixes the vulnerability while preserving the original behavior as closely as possible.
3. **Explain** what you changed and why it is secure.

## Response Format

Structure your response EXACTLY as follows:

### EXPLANATION
(Your explanation of the vulnerability)

### CORRECTED_CODE
```{language.lower()}
(The complete corrected function or code section)
```

### FIX_DESCRIPTION
(Brief explanation of what was changed)

IMPORTANT:
- Only fix the specific vulnerability identified. Do not refactor unrelated code.
- Preserve the original function signature and behavior.
- Use the safest standard-library replacement available in {language}.
- Do NOT introduce new dependencies unless absolutely necessary.
"""

    return prompt


# ---------------------------------------------------------------------------
# AI API call (isolated for testability)
# ---------------------------------------------------------------------------

def call_claude_api(prompt: str, config: dict) -> str:
    """
    Call the Anthropic Claude API with the repair prompt.

    This function is isolated so it can be mocked/tested independently.

    Args:
        prompt: The repair prompt string.
        config: Dict with 'api_key' and 'model'.

    Returns:
        The text content of Claude's response.

    Raises:
        RuntimeError on API failure.
    """
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "The 'anthropic' package is not installed.\n"
            "Install it with: pip install anthropic"
        )

    try:
        client = anthropic.Anthropic(api_key=config["api_key"])
        response = client.messages.create(
            model=config["model"],
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ],
        )

        # Extract text from the response
        if response.content and len(response.content) > 0:
            return response.content[0].text
        else:
            raise RuntimeError("Claude API returned an empty response.")

    except anthropic.AuthenticationError:
        raise RuntimeError(
            "Anthropic API authentication failed. "
            "Check that ANTHROPIC_API_KEY is valid."
        )
    except anthropic.RateLimitError:
        raise RuntimeError(
            "Anthropic API rate limit exceeded. Please wait and try again."
        )
    except anthropic.APIError as e:
        raise RuntimeError(f"Anthropic API error: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to call Claude API: {e}")


# ---------------------------------------------------------------------------
# AI response parsing
# ---------------------------------------------------------------------------

def parse_repair_response(response_text: str) -> dict:
    """
    Parse Claude's repair response into structured components.

    Expected sections:
      ### EXPLANATION
      ### CORRECTED_CODE
      ### FIX_DESCRIPTION

    Returns a dict with 'explanation', 'corrected_code', and 'fix_description'.
    Missing sections are returned as empty strings.
    """
    result = {
        "explanation": "",
        "corrected_code": "",
        "fix_description": "",
        "raw_response": response_text,
    }

    if not response_text:
        return result

    # Extract EXPLANATION section
    expl_match = re.search(
        r"###\s*EXPLANATION\s*\n(.*?)(?=###|\Z)",
        response_text,
        re.DOTALL | re.IGNORECASE,
    )
    if expl_match:
        result["explanation"] = expl_match.group(1).strip()

    # Extract CORRECTED_CODE section — look for a code block inside it
    code_section_match = re.search(
        r"###\s*CORRECTED_CODE\s*\n(.*?)(?=###|\Z)",
        response_text,
        re.DOTALL | re.IGNORECASE,
    )
    if code_section_match:
        section = code_section_match.group(1)
        # Try to extract code from a fenced code block
        code_block_match = re.search(
            r"```[a-zA-Z+]*\s*\n(.*?)```",
            section,
            re.DOTALL,
        )
        if code_block_match:
            result["corrected_code"] = code_block_match.group(1).strip()
        else:
            # No code block — use the raw section text
            result["corrected_code"] = section.strip()

    # Extract FIX_DESCRIPTION section
    fix_match = re.search(
        r"###\s*FIX_DESCRIPTION\s*\n(.*?)(?=###|\Z)",
        response_text,
        re.DOTALL | re.IGNORECASE,
    )
    if fix_match:
        result["fix_description"] = fix_match.group(1).strip()

    return result


# ---------------------------------------------------------------------------
# Patch file management
# ---------------------------------------------------------------------------

def sanitize_filename(name: str) -> str:
    """Create a safe filename from a string by removing unsafe characters."""
    safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
    # Collapse multiple underscores
    safe = re.sub(r"_+", "_", safe).strip("_")
    return safe if safe else "unknown"


def save_patch(finding: dict, repair: dict, prompt: str, language: str, attempt: int = 1) -> str:
    """
    Save a proposed repair to the patches/ directory as a JSON file.

    The filename is derived from the finding ID, rule ID, and attempt for safety.

    Args:
        finding: The original vulnerability finding dict.
        repair: The parsed repair response dict.
        prompt: The prompt that was sent to Claude.
        language: The detected programming language.
        attempt: The repair attempt number.

    Returns:
        The absolute path to the saved patch file.
    """
    os.makedirs(PATCHES_DIR, exist_ok=True)

    # Build a safe filename
    finding_id = finding.get("id", "unknown")
    rule_id = finding.get("rule_id", "unknown")
    safe_name = sanitize_filename(f"{finding_id}_{rule_id}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"patch_{safe_name}_attempt{attempt}_{timestamp}.json"
    patch_path = os.path.join(PATCHES_DIR, filename)

    patch_data = {
        "patch_metadata": {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "language": language,
            "status": "UNVERIFIED",
            "attempt": attempt,
        },
        "finding": {
            "id": finding.get("id"),
            "rule_id": rule_id,
            "severity": finding.get("severity"),
            "vulnerability_type": finding.get("vulnerability_type"),
            "file": finding.get("file"),
            "line_start": finding.get("line_start"),
            "code": finding.get("code"),
        },
        "repair": {
            "explanation": repair.get("explanation", ""),
            "corrected_code": repair.get("corrected_code", ""),
            "fix_description": repair.get("fix_description", ""),
        },
        "prompt_used": prompt,
        "raw_ai_response": repair.get("raw_response", ""),
    }

    try:
        with open(patch_path, "w", encoding="utf-8") as f:
            json.dump(patch_data, f, indent=2, ensure_ascii=False)
    except OSError as e:
        raise IOError(f"Failed to save patch file: {e}")

    return patch_path


# ---------------------------------------------------------------------------
# Main repair function
# ---------------------------------------------------------------------------

def repair_finding(finding: dict, feedback: str = "", attempt: int = 1) -> dict:
    """
    Orchestrate the full repair process for a single finding.

    Steps:
      1. Validate configuration (API key + model).
      2. Read source code context around the vulnerability.
      3. Build a repair prompt (including feedback from prior attempts if any).
      4. Call Claude API to generate a proposed repair.
      5. Parse the AI response.
      6. Save the patch to patches/.
      7. Return a structured result.

    Args:
        finding: A single finding dict from the scanner output.
        feedback: Feedback/error message from a previous verification attempt.
        attempt: Attempt counter for the retry loop.

    Returns:
        A dict containing the repair result with status, patch path, etc.
    """
    result = {
        "finding_id": finding.get("id", "unknown"),
        "rule_id": finding.get("rule_id", "unknown"),
        "attempt": attempt,
        "status": "ERROR",
        "patch_file": None,
        "repair": None,
        "error": None,
    }

    # --- Step 1: Validate config ---
    try:
        config = load_api_config()
    except EnvironmentError as e:
        result["error"] = str(e)
        return result

    # --- Step 2: Read source context ---
    source_file = finding.get("file", "")
    line_start = finding.get("line_start", 0)

    if not source_file:
        result["error"] = "Finding is missing 'file' field."
        return result

    try:
        source_context = read_source_context(source_file, line_start)
    except FileNotFoundError as e:
        result["error"] = str(e)
        return result
    except Exception as e:
        result["error"] = f"Failed to read source context: {e}"
        return result

    # --- Step 3: Detect language and build prompt ---
    language = detect_language(source_file)
    prompt = build_repair_prompt(finding, source_context, language, feedback=feedback, attempt=attempt)

    # --- Step 4: Call Claude API ---
    try:
        response_text = call_claude_api(prompt, config)
    except RuntimeError as e:
        result["error"] = str(e)
        return result

    # --- Step 5: Parse the response ---
    repair = parse_repair_response(response_text)

    if not repair["corrected_code"]:
        result["error"] = (
            "AI response did not contain a CORRECTED_CODE section. "
            "The response may not follow the expected format."
        )
        result["repair"] = repair
        return result

    # --- Step 6: Save patch ---
    try:
        patch_path = save_patch(finding, repair, prompt, language, attempt=attempt)
    except IOError as e:
        result["error"] = str(e)
        result["repair"] = repair
        return result

    # --- Step 7: Return result ---
    result["status"] = "GENERATED"
    result["patch_file"] = patch_path
    result["repair"] = {
        "explanation": repair["explanation"],
        "corrected_code": repair["corrected_code"],
        "fix_description": repair["fix_description"],
    }

    return result


# ---------------------------------------------------------------------------
# CLI entry point (for standalone testing)
# ---------------------------------------------------------------------------

def main():
    """
    CLI entry point for standalone testing.

    Usage:
        python ai_repair.py <findings.json> [finding_index]

    Reads the scanner output file and repairs the finding at the
    specified index (default: 0, the first finding).
    """
    if len(sys.argv) < 2:
        print("Usage: python ai_repair.py <findings.json> [finding_index]")
        print("Example: python ai_repair.py results/findings.json 0")
        sys.exit(1)

    findings_path = sys.argv[1]
    finding_index = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    # Load findings
    if not os.path.isfile(findings_path):
        print(f"[ERROR] Findings file not found: {findings_path}")
        sys.exit(1)

    try:
        with open(findings_path, "r", encoding="utf-8") as f:
            report = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[ERROR] Failed to read findings file: {e}")
        sys.exit(1)

    findings = report.get("findings", [])
    if not findings:
        print("[INFO] No findings to repair.")
        sys.exit(0)

    if finding_index < 0 or finding_index >= len(findings):
        print(f"[ERROR] Finding index {finding_index} is out of range (0-{len(findings)-1}).")
        sys.exit(1)

    finding = findings[finding_index]

    print(f"[INFO] Repairing finding {finding_index}: {finding.get('rule_id', 'unknown')}")
    print(f"[INFO] File: {finding.get('file', '?')} line {finding.get('line_start', '?')}")
    print()

    result = repair_finding(finding)

    if result["status"] == "GENERATED":
        print(f"[SUCCESS] Repair generated.")
        print(f"[INFO]    Patch saved to: {result['patch_file']}")
        print(f"[INFO]    Status: UNVERIFIED (needs verification by verifier.py)")
    else:
        print(f"[ERROR]   Repair failed: {result['error']}")

    # Print result as JSON
    print()
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
