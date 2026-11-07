#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
python="$script_dir/../../.venv/bin/python"
if [ ! -x "$python" ]; then
  python="$script_dir/../.venv/bin/python"
fi
exec "$python" "$script_dir/run_checks.py" "$@"
