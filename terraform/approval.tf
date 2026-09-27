# Durable pending-approval records for REQUIRE_APPROVAL (survives Lambda cold starts).

resource "aws_dynamodb_table" "pending_approvals" {
  name         = "soar-pending-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = {
    Name = "SOAR-Pending-Approvals"
  }
}

resource "aws_iam_policy" "soar_approval_store" {
  name        = "SOAR-ApprovalStore-Policy"
  description = "Allow SOAR Lambdas to read and write pending approval records"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PendingApprovalItems"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
        ]
        Resource = aws_dynamodb_table.pending_approvals.arn
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_approval_store" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.soar_approval_store.arn
}

locals {
  approval_env = {
    APPROVAL_STORE = "dynamodb"
    APPROVAL_TABLE = aws_dynamodb_table.pending_approvals.name
  }
}
