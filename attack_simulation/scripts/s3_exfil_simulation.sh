#!/bin/bash
# Simulation script to trigger S3 data exfiltration detection
# This script simulates large volume S3 downloads to test the SOAR playbook

BUCKET_NAME=$1
REGION=${2:-"us-east-1"}

if [ -z "$BUCKET_NAME" ]; then
    echo "Usage: ./s3_exfil_simulation.sh <bucket-name> [region]"
    echo "Example: ./s3_exfil_simulation.sh my-test-bucket us-west-2"
    exit 1
fi

echo "[*] Starting S3 data exfiltration simulation..."
echo "[*] Target bucket: $BUCKET_NAME"
echo "[*] Region: $REGION"

# Create some test files to upload
echo "[*] Creating test files..."
dd if=/dev/zero of=test_file_1MB.bin bs=1M count=1 2>/dev/null
dd if=/dev/zero of=test_file_10MB.bin bs=1M count=10 2>/dev/null
dd if=/dev/zero of=test_file_100MB.bin bs=1M count=100 2>/dev/null

# Upload files to bucket
echo "[*] Uploading test files to bucket..."
aws s3 cp test_file_1MB.bin s3://$BUCKET_NAME/ --region $REGION
aws s3 cp test_file_10MB.bin s3://$BUCKET_NAME/ --region $REGION
aws s3 cp test_file_100MB.bin s3://$BUCKET_NAME/ --region $REGION

# Simulate high-frequency downloads
echo "[*] Simulating high-frequency downloads..."
for i in {1..50}; do
    aws s3 cp s3://$BUCKET_NAME/test_file_1MB.bin ./downloaded_${i}.bin --region $REGION &
    if [ $((i % 10)) -eq 0 ]; then
        wait
        echo "[*] Completed batch $((i/10)) of downloads"
    fi
done

wait

# Simulate large volume download
echo "[*] Simulating large volume download..."
for i in {1..10}; do
    aws s3 cp s3://$BUCKET_NAME/test_file_100MB.bin ./large_download_${i}.bin --region $REGION &
done

wait

# Clean up local files
echo "[*] Cleaning up local files..."
rm -f test_file_*.bin downloaded_*.bin large_download_*.bin

echo "[+] S3 exfiltration simulation complete!"
echo "[*] Check your CloudTrail logs and Lambda function logs for detection events"
echo "[*] The SOAR playbook should trigger if thresholds are exceeded"
