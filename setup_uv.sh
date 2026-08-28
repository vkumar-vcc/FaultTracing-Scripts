#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv was not found. Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv was installed but is not available on PATH. Restart the shell and run this script again." >&2
  exit 1
fi

echo "Initializing Git submodules..."
git submodule update --init --recursive

echo "Syncing the uv project environment..."
uv sync

if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "Warning: tkinter is not available. Install it with your system package manager, for example:"
  echo "  sudo apt-get install python3-tk"
fi

echo "Setup complete. Activate the environment with:"
echo "  source .venv/bin/activate"
