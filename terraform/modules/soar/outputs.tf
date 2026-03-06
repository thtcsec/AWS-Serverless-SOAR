output "main_queue_url" {
  description = "URL of the main SQS queue"
  value       = aws_sqs_queue.main_queue.id
}

output "main_queue_arn" {
  description = "ARN of the main SQS queue"
  value       = aws_sqs_queue.main_queue.arn
}

output "dlq_url" {
  description = "URL of the dead letter queue"
  value       = aws_sqs_queue.dlq.id
}

output "dlq_arn" {
  description = "ARN of the dead letter queue"
  value       = aws_sqs_queue.dlq.arn
}

output "step_function_arn" {
  description = "ARN of the Step Function state machine"
  value       = aws_sfn_state_machine.incident_response.arn
}

output "step_function_name" {
  description = "Name of the Step Function state machine"
  value       = aws_sfn_state_machine.incident_response.name
}

output "ecs_cluster_name" {
  description = "Name of the ECS cluster"
  value       = aws_ecs_cluster.soar_workers.name
}

output "ecs_service_name" {
  description = "Name of the ECS service"
  value       = aws_ecs_service.isolation_worker.name
}

output "ecs_task_definition_arn" {
  description = "ARN of the ECS task definition"
  value       = aws_ecs_task_definition.isolation_worker.arn
}
