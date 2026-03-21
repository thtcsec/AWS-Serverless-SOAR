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


# ---------------------------------------------------------------------------
# RDS CloudTrail Event Models (Nhóm 1)
# ---------------------------------------------------------------------------

RISKY_RDS_METHODS: list[str] = [
    "ModifyDBInstance",
    "DeleteDBInstance",
    "CreateDBInstanceReadReplica",
    "ModifyDBClusterSnapshotAttribute",
    "AuthorizeDBSecurityGroupIngress",
    "RestoreDBInstanceFromDBSnapshot",
]


class RDSCloudTrailDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    eventSource: str = "rds.amazonaws.com"
    eventName: str
    requestParameters: dict[str, Any] | None = None
    userIdentity: dict[str, Any] = {}
    sourceIPAddress: str | None = None

    @property
    def dbInstanceIdentifier(self) -> str:
        params = self.requestParameters or {}
        return str(params.get("dBInstanceIdentifier", params.get("dbInstanceIdentifier", "")))

    @property
    def is_risky(self) -> bool:
        return self.eventName in RISKY_RDS_METHODS


class RDSCloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: Literal["aws.rds"]
    detail: RDSCloudTrailDetail


# ---------------------------------------------------------------------------
# EKS GuardDuty Event Models (Nhóm 2)
# ---------------------------------------------------------------------------


class EKSGuardDutyEvent(BaseModel):
    """GuardDuty event for EKS runtime threats."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    version: str = ""
    id: str = ""
    detail_type: str = Field("GuardDuty Finding", alias="detail-type")
    source: str = "aws.guardduty"
    account: str = ""
    time: str = ""
    region: str = ""
    resources: list[str] = []
    detail: GuardDutyDetail

    @property
    def is_eks_runtime_threat(self) -> bool:
        return self.detail.type.startswith("EKS:")


# ---------------------------------------------------------------------------
# CodePipeline / CodeBuild Event Models (Nhóm 3)
# ---------------------------------------------------------------------------

RISKY_CICD_METHODS: list[str] = [
    "UpdatePipeline",
    "PutJobSuccessResult",
    "StartBuild",
    "BatchGetProjects",
    "UpdateProject",
    "CreatePipeline",
    "DeletePipeline",
]


class CodePipelineDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")
    eventSource: str
    eventName: str
    userIdentity: dict[str, Any] = {}
    sourceIPAddress: str | None = None
    requestParameters: dict[str, Any] | None = None

    @property
    def is_supply_chain_risk(self) -> bool:
        return self.eventName in RISKY_CICD_METHODS


class CodePipelineEvent(BaseModel):
    model_config = ConfigDict(extra="ignore")
    source: str  # "aws.codepipeline" or "aws.codebuild"
    detail: CodePipelineDetail
