output "main_queue_url" {
  description = "URL of the main SQS queue"
  value       = aws_sqs_queue.main_queue.url
}

output "main_queue_arn" {
  description = "ARN of the main SQS queue"
  value       = aws_sqs_queue.main_queue.arn
}

output "dlq_url" {
  description = "URL of the dead letter queue"
  value       = aws_sqs_queue.dlq.url
}

output "dlq_arn" {
  description = "ARN of the dead letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "worker_queue_url" {
  description = "URL of the worker SQS queue"
  value       = aws_sqs_queue.worker_queue.url
}

output "worker_queue_arn" {
  description = "ARN of the worker SQS queue"
  value       = aws_sqs_queue.worker_queue.arn
}

output "worker_dlq_url" {
  description = "URL of the worker dead letter queue"
  value       = aws_sqs_queue.worker_dlq.url
}

output "guardduty_workflow_arn" {
  description = "ARN of the GuardDuty incident response Step Function"
  value       = aws_sfn_state_machine.guardduty_incident_response.arn
}

output "guardduty_workflow_name" {
  description = "Name of the GuardDuty incident response Step Function"
  value       = aws_sfn_state_machine.guardduty_incident_response.name
}

output "iam_workflow_arn" {
  description = "ARN of the IAM compromise response Step Function"
  value       = aws_sfn_state_machine.iam_compromise_response.arn
}

output "iam_workflow_name" {
  description = "Name of the IAM compromise response Step Function"
  value       = aws_sfn_state_machine.iam_compromise_response.name
}

output "s3_workflow_arn" {
  description = "ARN of the S3 exfiltration response Step Function"
  value       = aws_sfn_state_machine.s3_exfiltration_response.arn
}

output "s3_workflow_name" {
  description = "Name of the S3 exfiltration response Step Function"
  value       = aws_sfn_state_machine.s3_exfiltration_response.name
}

output "ecs_cluster_id" {
  description = "ID of the ECS cluster"
  value       = aws_ecs_cluster.soar_workers.id
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.soar_workers.name
}

output "forensics_worker_service_name" {
  description = "Name of the forensics worker ECS service"
  value       = aws_ecs_service.forensics_worker_service.name
}

output "isolation_worker_service_name" {
  description = "Name of the isolation worker ECS service"
  value       = aws_ecs_service.isolation_worker_service.name
}

output "report_worker_service_name" {
  description = "Name of the report worker ECS service"
  value       = aws_ecs_service.report_worker_service.name
}

output "forensics_task_definition_arn" {
  description = "ARN of the forensics worker task definition"
  value       = aws_ecs_task_definition.forensics_worker.arn
}

output "isolation_task_definition_arn" {
  description = "ARN of the isolation worker task definition"
  value       = aws_ecs_task_definition.isolation_worker.arn
}

output "report_task_definition_arn" {
  description = "ARN of the report worker task definition"
  value       = aws_ecs_task_definition.report_worker.arn
}

output "forensics_ecr_repository_url" {
  description = "URL of the forensics worker ECR repository"
  value       = aws_ecr_repository.forensics_worker.repository_url
}

output "isolation_ecr_repository_url" {
  description = "URL of the isolation worker ECR repository"
  value       = aws_ecr_repository.isolation_worker.repository_url
}

output "report_ecr_repository_url" {
  description = "URL of the report worker ECR repository"
  value       = aws_ecr_repository.report_worker.repository_url
}

output "workers_alb_dns_name" {
  description = "DNS name of the workers ALB"
  value       = aws_lb.workers_alb.dns_name
}

output "workers_alb_zone_id" {
  description = "Zone ID of the workers ALB"
  value       = aws_lb.workers_alb.zone_id
}

output "incident_reports_bucket" {
  description = "Name of the incident reports S3 bucket"
  value       = aws_s3_bucket.incident_reports.id
}

output "soar_alerts_topic_arn" {
  description = "ARN of the SOAR alerts SNS topic"
  value       = aws_sns_topic.soar_alerts.arn
}

output "ecs_log_group" {
  description = "Name of the ECS CloudWatch log group"
  value       = aws_cloudwatch_log_group.ecs_workers.name
}

output "isolation_security_group_id" {
  description = "ID of the isolation security group"
  value       = aws_security_group.isolation_sg.id
}

output "ecs_tasks_security_group_id" {
  description = "ID of the ECS tasks security group"
  value       = aws_security_group.ecs_tasks_sg.id
}

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.soar_vpc.id
}
