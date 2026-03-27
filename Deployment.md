# 🚀 Deployment Guide: AWS Serverless SOAR

This guide walks you through deploying the complete Serverless SOAR platform onto your AWS account using the provided automated script.

## 📋 Prerequisites

Before you begin, ensure you have the following installed and configured on your local machine:

1.  **AWS CLI:** Installed and configured with Administrator access (`aws configure`).
2.  **Terraform:** Version 1.5.0 or newer.
3.  **Docker:** Required for building and pushing the Fargate Forensics Worker container.
4.  **Bash:** (Windows users can use Git Bash or WSL).

## 🛠️ Automated Deployment

We provide an all-in-one deployment script at `scripts/deploy.sh`. This script will:
1. Initialize the Terraform backend (S3 bucket + DynamoDB lock).
2. Build the Docker images for the ECS Forensic Workers and push them to ECR.
3. Deploy all AWS infrastructure using Terraform.
4. Help you configure basic integrations.

### Step-by-Step

1. **Clone the project:**
   ```bash
   git clone https://github.com/thtcsec/AWS-Serverless-SOAR.git
   cd AWS-Serverless-SOAR
   ```

2. **Run the deployment script:**
   ```bash
   # Make the script executable
   chmod +x ./scripts/deploy.sh
   
   # Deploy the 'prod' environment
   ./scripts/deploy.sh prod deploy
   ```

3. **Provide API Keys (Interactive):**
   During deployment, the script will prompt you for your `VirusTotal` and `AbuseIPDB` API keys so it can configure Threat Intelligence enrichment. You can skip this and configure them later.

4. **Verify Email Subscription:**
   Terraform will ask for an `alert_email` variable during the apply phase. After deployment finishes, **check your email inbox** and click the AWS SNS confirmation link to receive security alerts.

---

## 🔗 Configuring Integrations

After deployment, you need to provide the secrets for your integrations securely via AWS Systems Manager (SSM) Parameter Store. 

### 1. Slack (Real-time Alerts)
Create an incoming webhook in your Slack workspace and save it:
```bash
aws ssm put-parameter \
  --name "/soar/slack/webhook_url" \
  --value "YOUR_WEBHOOK_URL" \
  --type "SecureString"
```

### 2. Jira (Forensic Tracking)
```bash
aws ssm put-parameter --name "/soar/jira/url" --value "https://your-domain.atlassian.net" --type "String"
aws ssm put-parameter --name "/soar/jira/username" --value "email@example.com" --type "String"
aws ssm put-parameter --name "/soar/jira/api_token" --value "YOUR_JIRA_TOKEN" --type "SecureString"
aws ssm put-parameter --name "/soar/jira/project_key" --value "SEC" --type "String"
```

### 3. Threat Intelligence
If you skipped the prompt during deployment:
```bash
aws ssm put-parameter --name "/soar/virustotal/api_key" --value "YOUR_VT_KEY" --type "SecureString"
aws ssm put-parameter --name "/soar/abuseipdb/api_key" --value "YOUR_ABUSEIPDB_KEY" --type "SecureString"
```

---

## 🧪 Testing the Deployment

We provide a built-in Attack Simulator to instantly test if the SOAR platform works.

```bash
# Run the Red Team simulator container
docker compose run --rm attacker
```
From the interactive menu, select `1` to trigger the EC2 Crypto Miner attack. Within ~15-30 seconds, you should receive a Slack alert, and the targeted EC2 instance will be isolated.

## 🧹 Cleanup / Teardown

To destroy all deployed resources and stop incurring costs:
```bash
./scripts/deploy.sh prod cleanup
```
