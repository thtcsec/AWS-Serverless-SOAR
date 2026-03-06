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
