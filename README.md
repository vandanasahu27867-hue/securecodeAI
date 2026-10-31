# AI Code Security

An automated security analysis and bounded AI repair system for C/C++, Python, and Java codebases.

AI Code Security detects dangerous security vulnerabilities, generates context-aware secure fixes using an AI repair agent, and automatically verifies proposed patches through sandboxed compilation, syntax checking, and static re-scanning.

---

## Architecture Overview

```text
               +-----------------------+
               |   Source Code File    |
               |  (C/C++, Python, Java)|
               +-----------------------+
                           |
                           v
               +-----------------------+
               |      scanner.py       |
               |  (Semgrep Integration)|
               +-----------------------+
                           |
                           v
               +-----------------------+
               | results/findings.json |
               +-----------------------+
                           |
                           v
              +-------------------------+
       +----->|  Bounded Repair Loop    |<----+
       |      |    (1 .. max_attempts)  |     |
       |      +-------------------------+     |
       |                   |                  |
       |                   v                  |
       |      +-------------------------+     |
       |      |       ai_repair.py      |     |
       |      |  (Claude API Fix Agent) |     |
       |      +-------------------------+     |
       |                   |                  |
       |                   v                  |
       |      +-------------------------+     |
       |      |       verifier.py       |     |
       |      | - Temporary Copy        |     |
       |      | - Compiler / Syntax     |     |
       |      | - Semgrep Re-scan       |     |
       |      +-------------------------+     |
       |                   |                  |
       |             [Pass / Fail?]           |
       |                   |                  |
  Retry with               +-------- Fail ----+
  Feedback                 |
                           v Pass (or Attempts Exhausted)
              +-------------------------+
              | results/final_report.json|
              |     & Console Summary   |
              +-------------------------+
```

---

## Supported Languages & 9 Vulnerability Rules

The MVP engine supports 3 major language ecosystems with 3 focused vulnerability rules each:

| # | Language | Rule ID | Target Pattern | Vulnerability Category | Severity |
|---|----------|---------|----------------|------------------------|----------|
| 1 | C / C++ | `c-strcpy-buffer-overflow` | `strcpy(...)` | Buffer Overflow | HIGH |
| 2 | C / C++ | `c-gets-buffer-overflow` | `gets(...)` | Buffer Overflow / Unsafe Input | CRITICAL |
| 3 | C / C++ | `c-sprintf-buffer-overflow` | `sprintf(...)` | Buffer Overflow | HIGH |
| 4 | Python | `py-eval-code-execution` | `eval(...)` | Dangerous Dynamic Execution | CRITICAL |
| 5 | Python | `py-exec-code-execution` | `exec(...)` | Dangerous Dynamic Execution | CRITICAL |
| 6 | Python | `py-subprocess-shell-injection` | `subprocess.*(..., shell=True)` | OS Command Injection | HIGH |
| 7 | Java | `java-runtime-exec-injection` | `Runtime.getRuntime().exec(...)` | OS Command Injection | HIGH |
| 8 | Java | `java-sql-injection` | `Statement.execute*(... + ...)` | SQL Injection | HIGH |
| 9 | Java | `java-unsafe-deserialization` | `new ObjectInputStream(...)` | Insecure Deserialization | CRITICAL |

Rule definitions and fix hints are located in `rules/security_rules.yml`.

---

## Security & Safety Principles

1. **Original Source Files Are Never Overwritten**: All repairs are evaluated on temporary isolated workspaces (`tempfile.mkdtemp`). The original code remains unmodified.
2. **AI-Generated Code Is Untrusted**: Generated patches are written to `patches/` as unverified artifacts until rigorously compiled and re-scanned.
3. **No Hardcoded Secrets**: Secrets such as `ANTHROPIC_API_KEY` are read exclusively from environment variables or `.env`. The `.env` file is excluded in `.gitignore`.
4. **Safe Process Execution**: All subprocess invocations use explicit argument lists without `shell=True` and enforce strict timeouts.
5. **Bounded Loop**: Repair attempts are bounded by a configurable maximum (default: 3) to prevent infinite loops.

---

## Installation & Setup

### Prerequisites

- Python 3.10+
- (Optional for full scan & re-scan) `semgrep` CLI
- (Optional for C/C++ verification) `gcc` / `g++`
- (Optional for Java verification) `javac` / JDK

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Environment Configuration

Copy the `.env` template and set your Anthropic API credentials when ready for AI repair:

```bash
# In .env:
ANTHROPIC_API_KEY=your_api_key_here
ANTHROPIC_MODEL=claude-sonnet-4-20250514
```

*(Note: API keys are only required for generating live Claude API repairs; static checks and verification logic run without an API key).*

---

## Usage

### Run Full Pipeline

```bash
python main.py <path_to_source_file> [--max-attempts N]
```

### Example Commands

#### Scan and Repair Python Code
```bash
python main.py test_code/vulnerable.py
```

#### Scan C Code with Custom Max Attempts
```bash
python main.py test_code/vulnerable.c --max-attempts 3
```

#### Scan Java Code
```bash
python main.py test_code/Vulnerable.java -m 5
```

#### Test Safe Code (Clean Verification)
```bash
python main.py test_code/safe.py
```

---

## AI Repair & Verification Workflow

### 1. Context Extraction (`ai_repair.py`)
When a vulnerability is detected:
- The module extracts the vulnerable code snippet plus surrounding lines (with line markers `>>>`).
- A prompt is constructed containing the rule ID, CWE, severity, vulnerability explanation, code context, and Semgrep fix hint.
- If this is a retry attempt, the prompt incorporates specific compiler stderr or re-scan feedback from the previous failed attempt.

### 2. Verification (`verifier.py`)
- The proposed fix is applied to a temporary duplicate file.
- The corresponding language compiler or syntax checker validates the code:
  - **C**: `gcc -o output -Wall -Wextra`
  - **C++**: `g++ -o output -Wall -Wextra`
  - **Python**: `python -m py_compile`
  - **Java**: `javac`
- If compilation succeeds and Semgrep is installed, a re-scan is performed to confirm the vulnerability rule no longer triggers.

### 3. Verdict Distinction
- **FULL Verification (`PASS - FULL`)**: Code compiles/parses AND Semgrep confirms the vulnerability is gone.
- **PARTIAL Verification (`PASS - PARTIAL`)**: Code compiles/parses, but Semgrep re-scan was skipped because Semgrep is not installed.
- **FAIL**: Code failed compilation or Semgrep detected that the vulnerability still persists.
- **ERROR**: File missing, empty AI response, or tool execution failure.

---

## Output & Reports

Every run outputs a summary to the console and generates:

`results/final_report.json`

The JSON report records:
- Metadata & timestamp
- Input file path
- Scan status & findings list
- Attempt-by-attempt history for each vulnerability (AI repair status, patch path, verification verdict, and failure details)
- Overall status: `CLEAN`, `REPAIRED`, `REPAIRED_PARTIAL`, `REPAIR_FAILED`, `VULNERABILITIES_FOUND`, or `SCAN_FAILED`
- System limitations and environmental notes

---

## Known Environment Limitations

- **Windows Semgrep Availability**: On some Windows environments, Semgrep execution may be restricted or blocked by local Application Control policies (WDAC / AppLocker) or missing wheels. The AI Code Security pipeline handles this gracefully:
  - If Semgrep is missing or blocked, the scan exits cleanly with `SCAN_FAILED` without crashing or fabricating findings.
  - During patch verification, if Semgrep re-scan is unavailable, the verdict is explicitly classified as **PARTIAL** verification, ensuring no false claims of full security are made.
