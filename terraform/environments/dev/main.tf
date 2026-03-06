# Development Environment Configuration
terraform {
  required_version = ">= 1.0"
  
  backend "s3" {
    bucket = "soar-tf-state-dev"
    key    = "dev/terraform.tfstate"
    region = "us-east-1"
    dynamodb_table = "terraform-lock-dev"
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

# ==========================================
# Events Module
# ==========================================
module "events" {
  source = "../../modules/events"

  environment       = var.environment
  main_queue_arn   = module.soar.main_queue_arn
  dlq_arn          = module.soar.dlq_arn
  dlq_url          = module.soar.dlq_url
  step_function_arn = module.soar.step_function_arn
  
  tags = merge(
    var.tags,
    {
      Environment = var.environment
    }
  )
}

# ==========================================
# Security Module
# ==========================================
module "security" {
  source = "../../modules/security"

  environment = var.environment
  
  enable_dev_account_access     = var.enable_dev_account_access
  enable_staging_account_access = var.enable_staging_account_access
  enable_prod_account_access    = var.enable_prod_account_access
  
  dev_account_id     = var.dev_account_id
  staging_account_id = var.staging_account_id
  prod_account_id    = var.prod_account_id
  
  dev_account_email     = var.dev_account_email
  staging_account_email = var.staging_account_email
  prod_account_email    = var.prod_account_email
  
  cross_account_external_id = var.cross_account_external_id
  
  tags = merge(
    var.tags,
    {
      Environment = var.environment
    }
  )
}

# ==========================================
# Integrations Module
# ==========================================
module "integrations" {
  source = "../../modules/integrations"

  environment = var.environment
  
  enable_slack_integration = var.enable_slack_integration
  enable_jira_integration = var.enable_jira_integration
  enable_siem_integration  = var.enable_siem_integration
  
  slack_webhook_url = var.slack_webhook_url
  jira_url          = var.jira_url
  jira_username     = var.jira_username
  jira_api_token    = var.jira_api_token
  siem_endpoint     = var.siem_endpoint
  siem_api_key      = var.siem_api_key
  
  tags = merge(
    var.tags,
    {
      Environment = var.environment
    }
  )
}
