"""Launcher called by `npm run dev` via concurrently."""
import os, sys, subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))
subprocess.run(
    [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"],
    check=True,
)
