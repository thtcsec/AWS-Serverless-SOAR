# AWS SOAR Deployment Script for PowerShell

Param(
    [string]$Environment = "prod",
    [string]$Action = "deploy"
)

$ErrorActionPreference = "Stop"

# Configuration
$ProjectRoot = Get-Item $PSScriptRoot\..
$TerraformDir = Join-Path $ProjectRoot.FullName "terraform"

Write-Host "[INFO] AWS SOAR Deployment" -ForegroundColor Blue
Write-Host "[INFO] Environment: $Environment" -ForegroundColor Blue
Write-Host "[INFO] Action: $Action" -ForegroundColor Blue

function Check-Prerequisites {
    Write-Host "[INFO] Checking prerequisites..." -ForegroundColor Blue
    
    if (!(Get-Command aws -ErrorAction SilentlyContinue)) {
        Write-Error "AWS CLI is not installed"
    }
    
    if (!(Get-Command terraform -ErrorAction SilentlyContinue)) {
        Write-Error "Terraform is not installed or not in PATH"
    }
    
    if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "Docker is not installed"
    }
    
    # Check AWS credentials
    try {
        aws sts get-caller-identity | Out-Null
    } catch {
        Write-Error "AWS credentials are not configured"
    }
    
    Write-Host "[SUCCESS] Prerequisites check passed" -ForegroundColor Green
}

function Init-TerraformBackend {
    param($env)
    Write-Host "[INFO] Initializing Terraform backend for $env..." -ForegroundColor Blue
    
    $envDir = Join-Path $TerraformDir "environments\$env"
    Push-Location $envDir
    
    $bucketName = "soar-tf-state-$env"
    $region = "ap-southeast-2" # Match your .env region
    
    # Check if bucket exists
    if (!(aws s3 ls "s3://$bucketName" 2>$null)) {
        Write-Host "[INFO] Creating S3 bucket: $bucketName" -ForegroundColor Blue
        aws s3api create-bucket --bucket $bucketName --region $region --create-bucket-configuration LocationConstraint=$region
        aws s3api put-bucket-versioning --bucket $bucketName --versioning-configuration Status=Enabled
    }
    
    terraform init
    Pop-Location
}

function Build-PushContainers {
    param($env)
    Write-Host "[INFO] Building and pushing containers..." -ForegroundColor Blue
    
    $accountId = (aws sts get-caller-identity --query Account --output text)
    $region = "ap-southeast-2"
    $registry = "$accountId.dkr.ecr.$region.amazonaws.com"
    
    # ECR Login
    aws ecr get-login-password --region $region | docker login --username AWS --password-stdin $registry
    
    # Build Workers
    $workers = @("isolation-worker", "forensics-worker")
    foreach ($worker in $workers) {
        $workerPath = Join-Path $ProjectRoot.FullName "containers\$worker"
        Write-Host "[INFO] Building $worker..." -ForegroundColor Blue
        Push-Location $workerPath
        docker build -t "soar-$worker:latest" .
        docker tag "soar-$worker:latest" "$registry/soar-$worker:latest"
        docker push "$registry/soar-$worker:latest"
        Pop-Location
    }
}

function Deploy-Infrastructure {
    param($env)
    Write-Host "[INFO] Deploying infrastructure..." -ForegroundColor Blue
    $envDir = Join-Path $TerraformDir "environments\$env"
    Push-Location $envDir
    terraform plan -out=tf.plan
    terraform apply tf.plan
    Remove-Item tf.plan
    Pop-Location
}

# Main Execution
try {
    switch ($Action) {
        "deploy" {
            Check-Prerequisites
            Init-TerraformBackend $Environment
            Build-PushContainers $Environment
            Deploy-Infrastructure $Environment
            Write-Host "[SUCCESS] Deployment complete!" -ForegroundColor Green
        }
        "cleanup" {
            $envDir = Join-Path $TerraformDir "environments\$Environment"
            Push-Location $envDir
            terraform destroy -auto-approve
            Pop-Location
        }
        Default {
            Write-Host "Usage: .\deploy.ps1 -Environment [dev|prod] -Action [deploy|cleanup]"
        }
    }
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
}
