from pydantic_settings import BaseSettings


class SOARConfig(BaseSettings):
    """SOAR Application Configuration using Pydantic Settings."""
    sns_topic_arn: str = ""
    exfiltration_threshold: int = 10737418240
    log_level: str = "INFO"
    evidence_bucket: str = ""
    metrics_namespace: str = "SOAR/IncidentResponse"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


# Global configuration instance
config = SOARConfig()
