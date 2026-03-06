import json
import logging
from datetime import datetime

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured CloudWatch logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "level": record.levelname,
            "message": record.getMessage(),
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "logger": record.name,
            "module": record.module,
        }
        
        # Insert exception info if exists
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
            
        return json.dumps(log_entry)

def setup_logger(name: str = "SOAR_Engine", level: int = logging.INFO) -> logging.Logger:
    """Initialize and configure the global JSON logger."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Prevent adding multiple handlers if setup is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        
    return logger

logger = setup_logger()
