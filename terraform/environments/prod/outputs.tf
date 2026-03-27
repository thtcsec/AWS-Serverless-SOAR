# Network Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "Public subnet IDs"
  value       = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  description = "Private subnet IDs"
  value       = module.network.private_subnet_ids
}

# SOAR Outputs
output "main_queue_url" {
  description = "Main SQS queue URL"
  value       = module.soar.main_queue_url
}

output "step_function_arn" {
  description = "Step Function ARN"
  value       = module.soar.step_function_arn
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = module.soar.ecs_cluster_name
}
