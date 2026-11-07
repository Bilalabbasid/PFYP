#!/usr/bin/env sh
# PhishGuard one-time setup for macOS / Linux. Run from the project folder:  sh setup.sh
set -e

PY=python3
command -v $PY >/dev/null 2>&1 || PY=python
command -v $PY >/dev/null 2>&1 || { echo "[ERROR] Python 3.11+ is required: https://www.python.org/downloads/"; exit 1; }

echo "[1/5] Creating virtual environment (.venv) ..."
[ -d .venv ] || $PY -m venv .venv

echo "[2/5] Installing dependencies (first time can take a few minutes) ..."
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -r requirements.txt

echo "[3/5] Creating .env from .env.example ..."
[ -f .env ] || cp .env.example .env

echo "[4/5] Training the optional machine-learning model ..."
.venv/bin/python ml/build_dataset.py
.venv/bin/python ml/train_model.py

echo "[5/5] Creating database, demo accounts and sample data ..."
.venv/bin/flask --app run seed-demo

echo
echo "Setup complete. Start the app with:   .venv/bin/python run.py"
echo "Then open http://127.0.0.1:5000  (demo admin: admin / Admin1234)"
