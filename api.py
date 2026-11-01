import os
import sys
import tempfile
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(BASE_DIR, "BACKEND")

if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

user_scripts = os.path.join(os.environ.get("APPDATA", ""), "Python", "Python314", "Scripts")
if os.path.exists(user_scripts) and user_scripts not in os.environ.get("PATH", ""):
    os.environ["PATH"] = user_scripts + os.pathsep + os.environ.get("PATH", "")

env_path = os.path.join(BACKEND_DIR, ".env")
load_dotenv(dotenv_path=env_path, override=True)

import main

app = FastAPI(title="Secure Code AI API")

# Smallest necessary CORS configuration to allow local frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "Secure Code AI API is running!"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/scan")
async def scan_code(file: UploadFile = File(...)):
    # Check supported file type
    allowed_extensions = {
        ".c", ".cpp", ".cc", ".cxx",
        ".py",
        ".java"
    }

    filename = file.filename or "uploaded_code"
    extension = os.path.splitext(filename)[1].lower()

    if extension not in allowed_extensions:
        return {
            "status": "error",
            "message": f"Unsupported file type: {extension}"
        }

    # Read uploaded code
    content = await file.read()

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=extension,
        dir=BACKEND_DIR
    ) as temp_file:

        temp_file.write(content)
        temp_file_path = temp_file.name

    try:
        # Run your existing scanner
        scan_result = main.run_scanner(temp_file_path)

        # If scanner fails, return the failure
        if not scan_result["success"]:
            return {
                "status": "SCAN_FAILED",
                "filename": filename,
                "scan": scan_result
            }

        # Get vulnerabilities
        findings = scan_result["findings"]

        # If no vulnerabilities
        if scan_result["total_findings"] == 0:
            report = main.generate_final_report(
                temp_file_path,
                scan_result,
                [],
                3
            )

            return {
                "status": "CLEAN",
                "filename": filename,
                "report": report
            }

        # Run your existing AI repair + verification pipeline
        repair_results = main.process_repairs_with_retry(
            findings,
            max_attempts=3
        )

        # Generate final report
        report = main.generate_final_report(
            temp_file_path,
            scan_result,
            repair_results,
            3
        )

        return {
            "status": report["overall_status"],
            "filename": filename,
            "report": report
        }

    finally:
        # Delete temporary uploaded file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)