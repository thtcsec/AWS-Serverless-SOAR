#!/bin/bash

# Ensure clear screen for the menu
clear

echo "=================================================="
echo "      AWS Serverless SOAR - Attack Simulator      "
echo "=================================================="
echo -e "\nPlease ensure that you have mounted your ~/.aws credentials"
echo -e "or passed the AWS_* environment variables into this container.\n"

# Verify AWS CLI identity as a quick check
echo "Checking AWS Identity..."
if aws sts get-caller-identity > /dev/null 2>&1; then
    echo "✅ Authentication successful."
else
    echo "⚠️  WARNING: Could not connect to AWS. Check your credentials."
fi

echo "--------------------------------------------------"
echo "1. Simulate EC2 Crypto Miner (Port Scan / DNS)"
echo "2. Simulate S3 Data Exfiltration"
echo "3. Simulate IAM Credential Compromise (SSRF)"
echo "4. Run All AWS Simulations"
echo "0. Exit"
echo "--------------------------------------------------"

read -p "Select an option [0-4]: " opt

case $opt in
    1)
        echo -e "\n[*] Running EC2 Crypto Miner Simulation..."
        /attacks/scripts/crypto_miner.sh
        /attacks/scripts/port_scan.sh
        ;;
    2)
        echo -e "\n[*] Running S3 Exfiltration Simulation..."
        /attacks/scripts/s3_exfil_simulation.sh
        ;;
    3)
        echo -e "\n[*] Running IAM Compromise Simulation..."
        /attacks/scripts/iam_compromise_simulation.sh
        /attacks/scripts/simulate_event.py
        ;;
    4)
        echo -e "\n[*] Running ALL AWS Simulations sequentially..."
        /attacks/scripts/crypto_miner.sh
        /attacks/scripts/port_scan.sh
        /attacks/scripts/s3_exfil_simulation.sh
        /attacks/scripts/iam_compromise_simulation.sh
        /attacks/scripts/simulate_event.py
        ;;
    0)
        echo "Exiting Attack Simulator."
        exit 0
        ;;
    *)
        echo "Invalid option. Exiting."
        exit 1
        ;;
esac

echo -e "\n[*] Simulation completed."
