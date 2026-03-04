#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
pip install fastapi uvicorn cryptography PyJWT -q
pip install -e . -q
echo "=== Tests ==="
PYTHONPATH=. python -m unittest discover -s tests -v
echo ""
echo "=== Serveur + Dashboard ==="
echo "Dashboard : http://localhost:8001/dashboard"
echo "API docs  : http://localhost:8001/docs"
echo ""
python -m uvicorn server.app:app --reload --port 8001
