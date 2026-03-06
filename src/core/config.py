import os
from pydantic import Field
from pydantic_settings import BaseSettings

class SOARConfig(BaseSettings):
    """SOAR Application Configuration using Pydantic Settings."""
    sns_topic_arn: str = Field(..., alias="SNS_TOPIC_ARN", description="ARN of the SNS topic for alerts")
    exfiltration_threshold: int = Field(10737418240, alias="EXFILTRATION_THRESHOLD", description="Bytes threshold for S3 exfiltration alert")
    log_level: str = Field("INFO", alias="LOG_LEVEL")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# Global configuration instance
config = SOARConfig()
