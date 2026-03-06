$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\..\.venv\Scripts\python.exe"
& $python -m pytest --cov=src tests/ --cov-report=xml
& $python -m flake8 src --count --select=E9,F63,F7,F82 --show-source --statistics
& $python -m bandit -r src -ll -ii
& $python -m mypy src --ignore-missing-imports
