from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class GuardDutyResource(BaseModel):
    instance_id: str | None = None
    bucket_name: str | None = None
    user_name: str | None = None


class GuardDutyDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schemaVersion: str
    accountId: str
    region: str
    partition: str
    id: str
    arn: str
    type: str
    service: dict[str, Any]
    severity: float
    createdAt: str
    updatedAt: str
    title: str
    description: str
    resource: dict[str, Any] | None = None
    resources: list[dict[str, Any]] | None = None


class GuardDutyEvent(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    version: str
    id: str
    detail_type: Literal["GuardDuty Finding"] = Field(alias="detail-type")
    source: Literal["aws.guardduty"]
    account: str
    time: str
    region: str
    resources: list[str]
    detail: GuardDutyDetail


class S3CloudTrailDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    eventName: str
    requestParameters: dict[str, Any] | None = None
    userIdentity: dict[str, Any]
    sourceIPAddress: str | None = None


class S3CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Literal["aws.s3"]
    detail: S3CloudTrailDetail


class IAMCloudTrailDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    eventName: str
    userIdentity: dict[str, Any]
    sourceIPAddress: str | None = None
    errorCode: str | None = None


class IAMCloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Literal["aws.iam"]
    detail: IAMCloudTrailDetail
