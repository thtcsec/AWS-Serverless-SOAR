#!/bin/bash
# Simulation script to trigger IAM compromise detection
# This script simulates suspicious IAM activities to test the SOAR playbook

USERNAME=${1:-"test-user"}
REGION=${2:-"us-east-1"}

echo "[*] Starting IAM compromise simulation..."
echo "[*] Target username: $USERNAME"
echo "[*] Region: $REGION"

# Create test user if it doesn't exist
echo "[*] Creating test user..."
aws iam create-user --user-name $USERNAME --region $REGION 2>/dev/null || echo "User already exists"

# Simulate privilege escalation attempts
echo "[*] Simulating privilege escalation attempts..."
aws iam attach-user-policy \
    --user-name $USERNAME \
    --policy-arn arn:aws:iam::aws:policy/PowerUserAccess \
    --region $REGION

# Create access key (suspicious activity)
echo "[*] Creating access key (suspicious activity)..."
aws iam create-access-key --user-name $USERNAME --region $REGION

# Simulate multiple failed login attempts
echo "[*] Simulating failed login attempts..."
for i in {1..5}; do
    # This will fail and generate CloudTrail events
    aws sts get-caller-identity --profile invalid-profile-$i 2>/dev/null || true
done

# Add user to privileged group
echo "[*] Adding user to privileged group..."
aws iam create-group --group-name TestAdminGroup --region $REGION 2>/dev/null || echo "Group already exists"
aws iam add-user-to-group --group-name TestAdminGroup --user-name $USERNAME --region $REGION

# Attach admin policy to group
echo "[*] Attaching admin policy to group..."
aws iam attach-group-policy \
    --group-name TestAdminGroup \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
    --region $REGION

# Create login profile (password reset)
echo "[*] Creating login profile..."
aws iam create-login-profile \
    --user-name $USERNAME \
    --password TempPassword123! \
    --password-reset-required \
    --region $REGION

echo "[+] IAM compromise simulation complete!"
echo "[*] Check your CloudTrail logs for:"
echo "    - User creation events"
echo "    - Policy attachment events"
echo "    - Access key creation"
echo "    - Group membership changes"
echo "    - Login profile creation"
echo "[*] The SOAR playbook should detect these suspicious activities"
