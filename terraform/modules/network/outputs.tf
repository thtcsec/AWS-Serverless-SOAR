output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.soar_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.soar_vpc.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public_subnets[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private_subnets[*].id
}

output "isolation_security_group_id" {
  description = "ID of the isolation security group"
  value       = aws_security_group.isolation_sg.id
}

output "worker_security_group_id" {
  description = "ID of the worker security group"
  value       = aws_security_group.worker_sg.id
}

output "vulnerable_security_group_id" {
  description = "ID of the vulnerable security group"
  value       = aws_security_group.vulnerable_sg.id
}

output "internet_gateway_id" {
  description = "ID of the internet gateway"
  value       = aws_internet_gateway.igw.id
}
