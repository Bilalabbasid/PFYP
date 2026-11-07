@echo off
REM Start PhishGuard on http://127.0.0.1:5000  (run setup.bat once first)
if not exist .venv (
  echo Run setup.bat first.
  exit /b 1
)
.venv\Scripts\python run.py
