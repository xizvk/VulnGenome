#!/usr/bin/env sh
set -eu
LITE_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(dirname -- "$LITE_ROOT")"
PYTHON="${PYTHON:-python3.12}"
export VULNGENOME_LITE_DATA_DIR="${VULNGENOME_LITE_DATA_DIR:-$LITE_ROOT/.runtime}"
mkdir -p "$VULNGENOME_LITE_DATA_DIR/pip-tmp"
export TMPDIR="$VULNGENOME_LITE_DATA_DIR/pip-tmp"

if [ ! -x "$LITE_ROOT/.venv/bin/python" ]; then
  "$PYTHON" -m venv "$LITE_ROOT/.venv"
fi
"$LITE_ROOT/.venv/bin/python" -c 'import sys; assert sys.version_info[:2] == (3, 12), f"VulnGenome Lite requires Python 3.12; found {sys.version_info.major}.{sys.version_info.minor}"'
if [ "${VULNGENOME_LITE_SKIP_INSTALL:-0}" != "1" ]; then
  "$LITE_ROOT/.venv/bin/python" -m pip install -r "$LITE_ROOT/requirements.txt"
fi
export PYTHONPATH="$REPO_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
cd "$LITE_ROOT/backend"
exec "$LITE_ROOT/.venv/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
