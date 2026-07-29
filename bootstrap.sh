#!/usr/bin/env bash
# Shared bootstrap for the argus / serve launchers.
# Ensures a project virtualenv exists and the Python requirements are installed
# (only re-installs when requirements.txt changes), then exports $ARGUS_PY.
_argus_bootstrap() {
  local here="$1"
  export PATH="$HOME/.local/bin:$PATH"          # bbot/ffuf usually live here
  local py="$here/.venv/bin/python"
  if [ ! -x "$py" ]; then
    echo "[argus] creating virtualenv (.venv) …" >&2
    python3 -m venv "$here/.venv" || { echo "[argus] venv creation failed" >&2; return 1; }
    py="$here/.venv/bin/python"
  fi
  local marker="$here/.venv/.deps-ok"
  if [ ! -f "$marker" ] || [ "$here/requirements.txt" -nt "$marker" ]; then
    echo "[argus] installing Python requirements …" >&2
    "$py" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    if "$py" -m pip install --quiet -r "$here/requirements.txt"; then
      touch "$marker"
    else
      echo "[argus] warning: some requirements failed to install (continuing)" >&2
    fi
  fi
  export ARGUS_PY="$py"
}
