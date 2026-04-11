from functools import lru_cache
from typing import Any

import boto3


class AWSClientFacade:
    """Centralized facade for accessing AWS Boto3 clients with memoization."""

    @classmethod
    @lru_cache
    def ec2(cls) -> Any:
        return boto3.client("ec2")

    @classmethod
    @lru_cache
    def s3(cls) -> Any:
        return boto3.client("s3")

    @classmethod
    @lru_cache
    def iam(cls) -> Any:
        return boto3.client("iam")

    @classmethod
    @lru_cache
    def sns(cls) -> Any:
        return boto3.client("sns")

    @classmethod
    @lru_cache
    def cloudtrail(cls) -> Any:
        return boto3.client("cloudtrail")

    @classmethod
    @lru_cache
    def cloudwatch(cls) -> Any:
        return boto3.client("cloudwatch")

    @classmethod
    @lru_cache
    def securityhub(cls) -> Any:
        return boto3.client("securityhub")

    @classmethod
    @lru_cache
    def rds(cls) -> Any:
        return boto3.client("rds")

    @classmethod
    @lru_cache
    def eks(cls) -> Any:
        return boto3.client("eks")

    @classmethod
    @lru_cache
    def codepipeline(cls) -> Any:
        return boto3.client("codepipeline")

    @classmethod
    @lru_cache
    def codebuild(cls) -> Any:
        return boto3.client("codebuild")

    @classmethod
    @lru_cache
    def wafv2(cls) -> Any:
        return boto3.client("wafv2")
