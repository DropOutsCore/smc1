# AVALOK — Start Scripts
# Run each in a separate terminal

# 1. Start the API backend (from c:\smc\)
# uvicorn securemailscope.api.app:app --host 0.0.0.0 --port 8000 --reload

# 2. Start the React frontend (from c:\smc\frontend\)
# npm run dev

# Quick one-liner to start backend:
import subprocess, sys, os

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    print("[AVALOK] Starting FastAPI backend on port 8000...")
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "securemailscope.api.app:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload",
    ])
