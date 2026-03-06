output "guardduty_rule_arn" {
  description = "ARN of the GuardDuty EventBridge rule"
  value       = aws_cloudwatch_event_rule.guardduty_findings.arn
}

output "cloudtrail_rule_arn" {
  description = "ARN of the CloudTrail EventBridge rule"
  value       = aws_cloudwatch_event_rule.cloudtrail_iam_events.arn
}

output "s3_rule_arn" {
  description = "ARN of the S3 EventBridge rule"
  value       = aws_cloudwatch_event_rule.s3_data_events.arn
}

output "queue_processor_lambda_arn" {
  description = "ARN of the queue processor Lambda function"
  value       = aws_lambda_function.queue_processor.arn
}

output "queue_processor_lambda_name" {
  description = "Name of the queue processor Lambda function"
  value       = aws_lambda_function.queue_processor.function_name
}

output "securityhub_rule_arn" {
  description = "ARN of the Security Hub EventBridge rule"
  value       = aws_cloudwatch_event_rule.securityhub_findings.arn
}

output "inspector_rule_arn" {
  description = "ARN of the Inspector EventBridge rule"
  value       = aws_cloudwatch_event_rule.inspector_findings.arn
}

output "macie_rule_arn" {
  description = "ARN of the Macie EventBridge rule"
  value       = aws_cloudwatch_event_rule.macie_findings.arn
}
