#!/bin/bash
# Fake crypto miner script that triggers GuardDuty instances
# This makes fake DNS requests to known mining pools. GuardDuty intercepts DNS logs.

echo "[*] Starting simulation of Crypto Mining..."
echo "[*] Making DNS queries to known malicious/mining pools..."
echo "[*] If AWS blocks these domains via DNS, you might need to use aws cli to generate sample findings."

while true; do
  curl -s -m 2 http://xmr.pool.minergate.com > /dev/null || echo "Ping xmr.pool.minergate.com"
  curl -s -m 2 http://pool.supportxmr.com > /dev/null || echo "Ping pool.supportxmr.com"
  curl -s -m 2 http://xmr-us-east1.nanopool.org > /dev/null || echo "Ping xmr-us-east1.nanopool.org"
  sleep 10
done
