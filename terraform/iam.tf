# ==========================================
# IAM Role for Lambda SOAR Responder
# ==========================================

# 1. Trust Relationship (Allow Lambda to assume this role)
resource "aws_iam_role" "lambda_exec_role" {
  name = "soar-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# 2. Attach basic execution privileges (for CloudWatch Logs)
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# 3. Custom Policy: The "SOAR Privileges"
# This policy is strictly scoped down (Least Privilege Principle constraint) 
# instead of granting 'AdministratorAccess' or full EC2 access.
resource "aws_iam_policy" "soar_incident_response_policy" {
  name        = "SOAR-IncidentResponse-Policy"
  description = "Allows Lambda to modify SGs, take snapshots, tag instances, and send SNS alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # EC2 isolation, IAM detachment, stop, IMDSv2 enforcement, and forensic snapshot permissions
        Sid    = "EC2ForensicsAndIsolation"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyInstanceMetadataOptions",
          "ec2:StopInstances",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:DescribeInstances",
          "ec2:DescribeIamInstanceProfileAssociations",
          "ec2:DisassociateIamInstanceProfile"
        ]
        Resource = "*" # In a production environment, restrict to specific VPCs/Instances using conditions
      },
      {
        # IAM Permissions to kill active attacker sessions by putting an inline deny policy
        Sid    = "IAMRevokeActiveSessions"
        Effect = "Allow"
        Action = [
          "iam:GetInstanceProfile",
          "iam:PutRolePolicy"
        ]
        Resource = "*" # Usually requires wildcards, or specific boundaries in Enterprise configs
      },
      {
        # SNS Notification Permission
        Sid      = "SNSAlerting"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.soar_alerts.arn
      }
    ]
  })
}

# 4. Attach Custom Policy to Lambda Role
resource "aws_iam_role_policy_attachment" "attach_soar_policy" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.soar_incident_response_policy.arn
}
