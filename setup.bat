@echo off
REM PhishGuard one-time setup for Windows. Run from the project folder:  setup.bat
setlocal

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found. Install Python 3.11+ from https://www.python.org/downloads/
  echo         and tick "Add python.exe to PATH" during installation.
  exit /b 1
)

echo [1/5] Creating virtual environment (.venv) ...
if not exist .venv (
  python -m venv .venv || exit /b 1
)

echo [2/5] Installing dependencies (first time can take a few minutes) ...
.venv\Scripts\python -m pip install --upgrade pip >nul
.venv\Scripts\python -m pip install -r requirements.txt || exit /b 1

echo [3/5] Creating .env from .env.example ...
if not exist .env copy .env.example .env >nul

echo [4/5] Training the optional machine-learning model ...
.venv\Scripts\python ml\build_dataset.py
.venv\Scripts\python ml\train_model.py

echo [5/5] Creating database, demo accounts and sample data ...
.venv\Scripts\flask --app run seed-demo

echo.
echo Setup complete. Start the app with:   run.bat
echo Then open http://127.0.0.1:5000  (demo admin: admin / Admin1234)
endlocal
