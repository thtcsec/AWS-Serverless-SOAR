# Production Environment Configuration
terraform {
  required_version = ">= 1.0"
  
  backend "s3" {
    bucket = "soar-tf-state-prod"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table = "terraform-lock-prod"
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ==========================================
# Network Module
# ==========================================
module "network" {
  source = "../../modules/network"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
  
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  availability_zones   = var.availability_zones
  
  enable_nat_gateway = var.enable_nat_gateway
  
  tags = merge(
    var.tags,
    {
      Environment = var.environment
    }
  )
}

# ==========================================
# SOAR Module
# ==========================================
module "soar" {
  source = "../../modules/soar"

  environment                = var.environment
  aws_region                = var.aws_region
  isolation_security_group_id = module.network.isolation_security_group_id
  worker_security_group_id   = module.network.worker_security_group_id
  private_subnet_ids         = module.network.private_subnet_ids
  container_registry         = var.container_registry
  worker_desired_count       = var.worker_desired_count
  approval_wait_time         = var.approval_wait_time
  
  tags = merge(
    var.tags,
    {
      Environment = var.environment
    }
  )
}
