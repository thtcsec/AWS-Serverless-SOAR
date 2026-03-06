output "soar_central_role_arn" {
  description = "ARN of the central SOAR execution role"
  value       = aws_iam_role.soar_central_role.arn
}

output "soar_cross_account_responder_role_arn" {
  description = "ARN of the cross-account responder role"
  value       = aws_iam_role.soar_cross_account_responder.arn
}

output "dev_account_access_role_arn" {
  description = "ARN of the dev account access role"
  value       = var.enable_dev_account_access ? aws_iam_role.dev_account_access[0].arn : null
}

output "staging_account_access_role_arn" {
  description = "ARN of the staging account access role"
  value       = var.enable_staging_account_access ? aws_iam_role.staging_account_access[0].arn : null
}

output "prod_account_access_role_arn" {
  description = "ARN of the production account access role"
  value       = var.enable_prod_account_access ? aws_iam_role.prod_account_access[0].arn : null
}

output "guardduty_detector_id" {
  description = "ID of the central GuardDuty detector"
  value       = aws_guardduty_detector.central_detector.id
}

output "central_logs_bucket_name" {
  description = "Name of the central logs S3 bucket"
  value       = aws_s3_bucket.central_logs.id
}

output "central_logs_bucket_arn" {
  description = "ARN of the central logs S3 bucket"
  value       = aws_s3_bucket.central_logs.arn
}

output "securityhub_account_id" {
  description = "ID of the Security Hub account"
  value       = aws_securityhub_account.main.id
}

output "inspector_enabler_id" {
  description = "ID of the Inspector enabler"
  value       = aws_inspector2_enabler.main.id
}

output "macie_account_id" {
  description = "ID of the Macie account"
  value       = aws_macie2_account.main.id
}

output "soar_kms_key_arn" {
  description = "ARN of the SOAR KMS key"
  value       = aws_kms_key.soar_key.arn
}
