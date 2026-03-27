# Enterprise SOAR Step Functions State Machine
# Defines the incident response workflow orchestration

resource "aws_sfn_state_machine" "guardduty_incident_response" {
  name     = "${var.environment}-guardduty-incident-response"
  role_arn = aws_iam_role.step_function_role.arn
  type     = "STANDARD"

  definition = <<EOF
{
  "Comment": "Enterprise SOAR - GuardDuty Incident Response Workflow",
  "StartAt": "DetectSeverity",
  "States": {
    "DetectSeverity": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.detect_severity.arn}",
      "Next": "Decision",
      "ResultPath": "$.severity_analysis",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "Next": "SendToDLQ"
        }
      ]
    },
    "Decision": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.severity_analysis.severity_level",
          "StringEquals": "CRITICAL",
          "Next": "IsolateInstance"
        },
        {
          "Variable": "$.severity_analysis.severity_level",
          "StringEquals": "HIGH",
          "Next": "RequireApproval"
        },
        {
          "Variable": "$.severity_analysis.severity_level",
          "StringEquals": "MEDIUM",
          "Next": "NotifyTeamMedium"
        }
      ],
      "Default": "LogAndDismiss"
    },
    "IsolateInstance": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke.invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.isolate_instance.arn}",
        "Payload": {
          "instance_id.$": "$.severity_analysis.instance_id",
          "reason": "CRITICAL severity threat detected"
        }
      },
      "Next": "CreateSnapshot",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "Next": "SendAlertIsolationFailed"
        }
      ]
    },
    "CreateSnapshot": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke.invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.create_snapshot.arn}",
        "Payload": {
          "instance_id.$": "$.severity_analysis.instance_id",
          "threat_type.$": "$.severity_analysis.threat_type"
        }
      },
      "Next": "EnrichThreatIntel",
      "Catch": [
        {
          "ErrorEquals": ["States.ALL"],
          "Next": "ContinueAfterSnapshot"
        }
      ]
    },
    "EnrichThreatIntel": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.enrich_threat_intel.arn}",
      "Next": "NotifyTeamCritical",
      "ResultPath": "$.threat_intel"
    },
    "NotifyTeamCritical": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "🚨 CRITICAL Security Alert - Instance Isolated",
        "Message": {
          "incident_type": "GuardDuty Finding",
          "severity": "CRITICAL",
          "instance_id.$": "$.severity_analysis.instance_id",
          "threat_type.$": "$.severity_analysis.threat_type",
          "actions_taken": ["instance_isolated", "snapshot_created", "threat_intel_enriched"],
          "next_steps": "Review and approve for termination if needed"
        }
      },
      "Next": "WaitForTerminationApproval"
    },
    "WaitForTerminationApproval": {
      "Type": "Wait",
      "Seconds": 3600,
      "Next": "CheckTerminationApproval"
    },
    "CheckTerminationApproval": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.check_approval.arn}",
      "Next": "TerminationDecision"
    },
    "TerminationDecision": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.approval_status",
          "StringEquals": "APPROVED",
          "Next": "TerminateInstance"
        },
        {
          "Variable": "$.approval_status",
          "StringEquals": "REJECTED",
          "Next": "RestoreInstance"
        }
      ],
      "Default": "TerminateInstance"
    },
    "TerminateInstance": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke.invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.terminate_instance.arn}",
        "Payload": {
          "instance_id.$": "$.severity_analysis.instance_id",
          "approval_status.$": "$.approval_status"
        }
      },
      "Next": "GenerateIncidentReport"
    },
    "RestoreInstance": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.restore_instance.arn}",
      "Next": "GenerateIncidentReport"
    },
    "RequireApproval": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "⚠️ HIGH Security Alert - Approval Required",
        "Message": {
          "incident_type": "GuardDuty Finding",
          "severity": "HIGH",
          "instance_id.$": "$.severity_analysis.instance_id",
          "threat_type.$": "$.severity_analysis.threat_type",
          "action_required": "Manual approval needed for isolation"
        }
      },
      "Next": "WaitForApproval"
    },
    "WaitForApproval": {
      "Type": "Wait",
      "Seconds": 7200,
      "Next": "CheckApproval"
    },
    "CheckApproval": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.check_approval.arn}",
      "Next": "ApprovalDecision"
    },
    "ApprovalDecision": {
      "Type": "Choice",
      "Choices": [
        {
          "Variable": "$.approval_status",
          "StringEquals": "APPROVED",
          "Next": "IsolateInstance"
        }
      ],
      "Default": "LogAndDismiss"
    },
    "NotifyTeamMedium": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "MEDIUM Security Alert - Investigation Required",
        "Message": {
          "incident_type": "GuardDuty Finding",
          "severity": "MEDIUM",
          "instance_id.$": "$.severity_analysis.instance_id",
          "threat_type.$": "$.severity_analysis.threat_type"
        }
      },
      "Next": "LogAndDismiss"
    },
    "GenerateIncidentReport": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.generate_report.arn}",
      "Next": "ForwardToSIEM"
    },
    "ForwardToSIEM": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.forward_to_siem.arn}",
      "Next": "End"
    },
    "SendToDLQ": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sqs:sendMessage",
      "Parameters": {
        "QueueUrl": "${aws_sqs_queue.dlq.url}",
        "MessageBody.$": "$"
      },
      "Next": "End"
    },
    "SendAlertIsolationFailed": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "🔴 SOAR Alert - Isolation Failed",
        "Message": {
          "incident_type": "SOAR Execution Error",
          "instance_id.$": "$.severity_analysis.instance_id",
          "error": "Instance isolation failed - manual intervention required"
        }
      },
      "Next": "SendToDLQ"
    },
    "ContinueAfterSnapshot": {
      "Type": "Pass",
      "Next": "NotifyTeamCritical"
    },
    "LogAndDismiss": {
      "Type": "Pass",
      "End": true
    },
    "End": {
      "Type": "Pass",
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-guardduty-sfn"
      Environment = var.environment
      Purpose     = "incident-response"
    }
  )
}

resource "aws_sfn_state_machine" "iam_compromise_response" {
  name     = "${var.environment}-iam-compromise-response"
  role_arn = aws_iam_role.step_function_role.arn
  type     = "STANDARD"

  definition = <<EOF
{
  "Comment": "Enterprise SOAR - IAM Compromise Response Workflow",
  "StartAt": "DetectCompromise",
  "States": {
    "DetectCompromise": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.detect_iam_compromise.arn}",
      "Next": "DisableAccessKeys",
      "ResultPath": "$.compromise_analysis"
    },
    "DisableAccessKeys": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.disable_iam_keys.arn}",
      "Next": "CreateNewKey",
      "ResultPath": "$.disabled_keys"
    },
    "CreateNewKey": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.create_iam_key.arn}",
      "Next": "RotateSecrets",
      "ResultPath": "$.new_key"
    },
    "RotateSecrets": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.rotate_secrets.arn}",
      "Next": "NotifyTeamIAM",
      "ResultPath": "$.rotated_secrets"
    },
    "NotifyTeamIAM": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "🔴 IAM Compromise Alert - Keys Rotated",
        "Message": {
          "incident_type": "IAM Compromise",
          "user_or_role.$": "$.compromise_analysis.user_arn",
          "actions_taken": ["access_keys_disabled", "new_key_created", "secrets_rotated"],
          "next_steps": "Review IAM usage and notify affected users"
        }
      },
      "Next": "End"
    },
    "End": {
      "Type": "Pass",
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-iam-sfn"
      Environment = var.environment
      Purpose     = "iam-response"
    }
  )
}

resource "aws_sfn_state_machine" "s3_exfiltration_response" {
  name     = "${var.environment}-s3-exfiltration-response"
  role_arn = aws_iam_role.step_function_role.arn
  type     = "STANDARD"

  definition = <<EOF
{
  "Comment": "Enterprise SOAR - S3 Data Exfiltration Response Workflow",
  "StartAt": "DetectExfiltration",
  "States": {
    "DetectExfiltration": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.detect_s3_exfil.arn}",
      "Next": "BlockBucketAccess",
      "ResultPath": "$.exfil_analysis"
    },
    "BlockBucketAccess": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.block_s3_access.arn}",
      "Next": "EnableBucketLogging",
      "ResultPath": "$.blocked_access"
    },
    "EnableBucketLogging": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.enable_s3_logging.arn}",
      "Next": "PreserveEvidence",
      "ResultPath": "$.logging_enabled"
    },
    "PreserveEvidence": {
      "Type": "Task",
      "Resource": "${aws_lambda_function.preserve_s3_evidence.arn}",
      "Next": "NotifyTeamS3",
      "ResultPath": "$.evidence_preserved"
    },
    "NotifyTeamS3": {
      "Type": "Task",
      "Resource": "arn:aws:states:::sns:publish",
      "Parameters": {
        "TopicArn": "${aws_sns_topic.soar_alerts.arn}",
        "Subject": "🔴 S3 Exfiltration Alert - Bucket Secured",
        "Message": {
          "incident_type": "S3 Data Exfiltration",
          "bucket_name.$": "$.exfil_analysis.bucket_name",
          "actions_taken": ["access_blocked", "logging_enabled", "evidence_preserved"],
          "data_at_risk.$": "$.exfil_analysis.data_size"
        }
      },
      "Next": "End"
    },
    "End": {
      "Type": "Pass",
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-s3-sfn"
      Environment = var.environment
      Purpose     = "s3-response"
    }
  )
}

# Lambda Functions referenced by Step Functions
resource "aws_lambda_function" "detect_severity" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-detect-severity"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/detect_severity.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }
}

resource "aws_lambda_function" "isolate_instance" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-isolate-instance"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/isolate_instance.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120

  environment {
    variables = {
      ISOLATION_SG_ID = aws_security_group.isolation_sg.id
    }
  }
}

resource "aws_lambda_function" "create_snapshot" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-create-snapshot"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/create_snapshot.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 180
}

resource "aws_lambda_function" "terminate_instance" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-terminate-instance"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/terminate_instance.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "check_approval" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-check-approval"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/check_approval.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
}

resource "aws_lambda_function" "enrich_threat_intel" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-enrich-threat-intel"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/enrich_threat_intel.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "restore_instance" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-restore-instance"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/restore_instance.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120
}

resource "aws_lambda_function" "generate_report" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-generate-report"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/generate_report.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "forward_to_siem" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-forward-to-siem"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/forward_to_siem.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
}

resource "aws_lambda_function" "detect_iam_compromise" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-detect-iam-compromise"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/detect_iam_compromise.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "disable_iam_keys" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-disable-iam-keys"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/disable_iam_keys.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "create_iam_key" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-create-iam-key"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/create_iam_key.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
}

resource "aws_lambda_function" "rotate_secrets" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-rotate-secrets"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/rotate_secrets.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120
}

resource "aws_lambda_function" "detect_s3_exfil" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-detect-s3-exfil"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/detect_s3_exfil.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "block_s3_access" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-block-s3-access"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/block_s3_access.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "enable_s3_logging" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-enable-s3-logging"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/enable_s3_logging.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60
}

resource "aws_lambda_function" "preserve_s3_evidence" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-preserve-s3-evidence"
  role             = aws_iam_role.step_function_role.arn
  handler          = "workflow/preserve_s3_evidence.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 120
}

# Security Group for Isolation (referenced by isolate_instance Lambda)
resource "aws_security_group" "isolation_sg" {
  name        = "${var.environment}-soar-isolation-sg"
  description = "Zero trust security group for isolating compromised instances"
  vpc_id      = aws_vpc.soar_vpc.id

  tags = {
    Name = "${var.environment}-soar-isolation-sg"
  }
}
