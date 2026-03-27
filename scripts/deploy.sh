#!/bin/bash

# SOAR Platform Deployment Script
# This script deploys the complete SOAR platform

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TERRAFORM_DIR="$PROJECT_ROOT/terraform"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI is not installed"
        exit 1
    fi
    
    # Check Terraform
    if ! command -v terraform &> /dev/null; then
        log_error "Terraform is not installed"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials are not configured"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Function to initialize Terraform backend
init_terraform_backend() {
    local environment=$1
    log_info "Initializing Terraform backend for $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Create S3 bucket for state if it doesn't exist
    local bucket_name="soar-tf-state-$environment"
    local region="us-east-1"
    
    if ! aws s3 ls "s3://$bucket_name" &> /dev/null; then
        log_info "Creating S3 bucket for Terraform state: $bucket_name"
        aws s3api create-bucket \
            --bucket "$bucket_name" \
            --region "$region" \
            --versioning-configuration Status=Enabled
        
        # Enable encryption
        aws s3api put-bucket-encryption \
            --bucket "$bucket_name" \
            --server-side-encryption-configuration '{
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }'
        
        # Create DynamoDB table for state locking
        local table_name="terraform-lock-$environment"
        log_info "Creating DynamoDB table for state locking: $table_name"
        
        aws dynamodb create-table \
            --table-name "$table_name" \
            --attribute-definitions AttributeName=LockID,AttributeType=S \
            --key-schema AttributeName=LockID,KeyType=HASH \
            --billing-mode PAY_PER_REQUEST \
            --region "$region" \
            --tags Key=Name,Value="soar-terraform-lock" Key=Environment,Value="$environment"
    fi
    
    terraform init
    
    log_success "Terraform backend initialized for $environment"
}

# Function to build and push containers
build_containers() {
    local environment=$1
    log_info "Building containers for $environment environment..."
    
    # Get AWS account ID and region
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    local region="us-east-1"
    local registry="$account_id.dkr.ecr.$region.amazonaws.com"
    
    # Login to ECR
    aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry"
    
    # Build isolation worker
    log_info "Building isolation worker container..."
    cd "$PROJECT_ROOT/containers/isolation-worker"
    docker build -t "soar-isolation-worker:latest" .
    docker tag "soar-isolation-worker:latest" "$registry/soar-isolation-worker:latest"
    docker push "$registry/soar-isolation-worker:latest"
    
    # Build forensics worker
    log_info "Building forensics worker container..."
    cd "$PROJECT_ROOT/containers/forensics-worker"
    docker build -t "soar-forensics-worker:latest" .
    docker tag "soar-forensics-worker:latest" "$registry/soar-forensics-worker:latest"
    docker push "$registry/soar-forensics-worker:latest"
    
    log_success "Containers built and pushed successfully"
}

# Function to deploy infrastructure
deploy_infrastructure() {
    local environment=$1
    log_info "Deploying infrastructure for $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Plan and apply
    terraform plan -out="terraform.plan"
    terraform apply "terraform.plan"
    
    # Clean up plan file
    rm -f "terraform.plan"
    
    log_success "Infrastructure deployed for $environment"
}

# Function to configure integrations
configure_integrations() {
    local environment=$1
    log_info "Configuring integrations for $environment environment..."
    
    # Slack integration
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        log_info "Configuring Slack integration..."
        aws ssm put-parameter \
            --name "/soar/slack/webhook_url" \
            --value "$SLACK_WEBHOOK_URL" \
            --type "SecureString" \
            --description "Slack webhook URL for SOAR notifications"
    fi
    
    # Jira integration
    if [[ -n "$JIRA_URL" && -n "$JIRA_USERNAME" && -n "$JIRA_API_TOKEN" ]]; then
        log_info "Configuring Jira integration..."
        aws ssm put-parameter \
            --name "/soar/jira/url" \
            --value "$JIRA_URL" \
            --type "SecureString" \
            --description "Jira instance URL"
        
        aws ssm put-parameter \
            --name "/soar/jira/username" \
            --value "$JIRA_USERNAME" \
            --type "SecureString" \
            --description "Jira API username"
        
        aws ssm put-parameter \
            --name "/soar/jira/api_token" \
            --value "$JIRA_API_TOKEN" \
            --type "SecureString" \
            --description "Jira API token"
    fi
    
    # SIEM integration
    if [[ -n "$SIEM_ENDPOINT" && -n "$SIEM_API_KEY" ]]; then
        log_info "Configuring SIEM integration..."
        aws ssm put-parameter \
            --name "/soar/siem/endpoint" \
            --value "$SIEM_ENDPOINT" \
            --type "SecureString" \
            --description "SIEM API endpoint"
        
        aws ssm put-parameter \
            --name "/soar/siem/api_key" \
            --value "$SIEM_API_KEY" \
            --type "SecureString" \
            --description "SIEM API key"
    fi
    
    log_success "Integrations configured for $environment"
}

# Function to run tests
run_tests() {
    local environment=$1
    log_info "Running tests for $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Get outputs
    local step_function_arn=$(terraform output -raw step_function_arn)
    local queue_processor_arn=$(terraform output -raw queue_processor_lambda_arn)
    
    # Test Step Function
    log_info "Testing Step Function..."
    aws stepfunctions start-execution \
        --state-machine-arn "$step_function_arn" \
        --input '{"test": true, "original_finding": {"id": "test-123", "severity": 7.0}}'
    
    # Test Lambda
    log_info "Testing Lambda function..."
    aws lambda invoke \
        --function-name "$queue_processor_arn" \
        --payload '{"test": true}' \
        /tmp/lambda_test_output.json
    
    log_success "Tests completed for $environment"
}

# Function to show deployment summary
show_summary() {
    local environment=$1
    log_info "Deployment summary for $environment environment:"
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    echo "=== Infrastructure Outputs ==="
    terraform output
    
    echo ""
    echo "=== Next Steps ==="
    echo "1. Configure your integrations in AWS Systems Manager Parameter Store"
    echo "2. Test the workflow by triggering a GuardDuty finding"
    echo "3. Monitor the execution in AWS Step Functions console"
    echo "4. Check notifications in your configured channels"
    
    echo ""
    echo "=== Useful Commands ==="
    echo "# View Step Functions:"
    echo "aws stepfunctions list-state-machines"
    echo ""
    echo "# View SQS queues:"
    echo "aws sqs list-queues"
    echo ""
    echo "# View Lambda functions:"
    echo "aws lambda list-functions --query 'Functions[?contains(FunctionName, \`soar\`)]'"
    echo ""
    echo "# View ECS services:"
    echo "aws ecs list-services --cluster $(terraform output -raw ecs_cluster_name)"
}

# Function to cleanup
cleanup() {
    local environment=$1
    log_warning "Cleaning up $environment environment..."
    
    cd "$TERRAFORM_DIR/environments/$environment"
    
    # Destroy infrastructure
    terraform destroy -auto-approve
    
    # Clean up containers (optional)
    read -p "Do you want to clean up container images? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        local account_id=$(aws sts get-caller-identity --query Account --output text)
        local region="us-east-1"
        local registry="$account_id.dkr.ecr.$region.amazonaws.com"
        
        aws ecr batch-delete-image-repository \
            --repository-name soar-isolation-worker \
            --force || true
        
        aws ecr batch-delete-image-repository \
            --repository-name soar-forensics-worker \
            --force || true
    fi
    
    log_success "Cleanup completed for $environment"
}

# Main deployment function
main() {
    local environment=${1:-"dev"}
    local action=${2:-"deploy"}
    
    log_info "SOAR Platform Deployment"
    log_info "Environment: $environment"
    log_info "Action: $action"
    
    case $action in
        "deploy")
            check_prerequisites
            init_terraform_backend "$environment"
            build_containers "$environment"
            deploy_infrastructure "$environment"
            configure_integrations "$environment"
            run_tests "$environment"
            show_summary "$environment"
            ;;
        "test")
            run_tests "$environment"
            ;;
        "cleanup")
            cleanup "$environment"
            ;;
        "help"|"-h"|"--help")
            echo "Usage: $0 [environment] [action]"
            echo ""
            echo "Environments:"
            echo "  dev         Development environment (default)"
            echo "  staging     Staging environment"
            echo "  prod        Production environment"
            echo ""
            echo "Actions:"
            echo "  deploy      Deploy the platform (default)"
            echo "  test        Run tests only"
            echo "  cleanup     Destroy all resources"
            echo "  help        Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  SLACK_WEBHOOK_URL    Slack webhook URL"
            echo "  JIRA_URL             Jira instance URL"
            echo "  JIRA_USERNAME        Jira API username"
            echo "  JIRA_API_TOKEN       Jira API token"
            echo "  SIEM_ENDPOINT        SIEM API endpoint"
            echo "  SIEM_API_KEY         SIEM API key"
            ;;
        *)
            log_error "Unknown action: $action"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
