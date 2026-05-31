"""DEPRECATED — use handlers.handle_event() via handlers.lambda_handler."""

from src.handlers import handle_event, lambda_handler

__all__ = ["handle_event", "lambda_handler"]
