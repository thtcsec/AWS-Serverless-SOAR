from pydantic import BaseModel, ConfigDict, Field
from typing import Literal, Dict, Any, Optional, List

class GuardDutyResource(BaseModel):
    instance_id: Optional[str] = None
    bucket_name: Optional[str] = None
    user_name: Optional[str] = None

class GuardDutyDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    schemaVersion: str
    accountId: str
    region: str
    partition: str
    id: str
    arn: str
    type: str
    service: Dict[str, Any]
    severity: float
    createdAt: str
    updatedAt: str
    title: str
    description: str
    resource: Optional[Dict[str, Any]] = None
    resources: Optional[List[Dict[str, Any]]] = None

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
    requestParameters: Optional[Dict[str, Any]] = None
    userIdentity: Dict[str, Any]
    sourceIPAddress: Optional[str] = None

class S3CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Literal["aws.s3"]
    detail: S3CloudTrailDetail

class IAMCloudTrailDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    eventName: str
    userIdentity: Dict[str, Any]
    sourceIPAddress: Optional[str] = None
    errorCode: Optional[str] = None

class IAMCloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Literal["aws.iam"]
    detail: IAMCloudTrailDetail
