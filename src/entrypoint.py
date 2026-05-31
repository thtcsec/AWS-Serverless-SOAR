"""
AWS SOAR — Lambda Transport Entrypoint

Thin wrapper for legacy handler paths. All logic lives in handlers.handle_event().
"""

from __future__ import annotations

from src.handlers import handle_event, lambda_handler

__all__ = ["handle_event", "lambda_handler"]
