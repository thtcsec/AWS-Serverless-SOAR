#!/bin/bash
# Simulation of outbound port scanning
# Scans random internal/external IP addresses on port 22

echo "[*] Starting outbound port scan simulation..."
echo "[*] Warning: Ensure this is authorized before running in corporate networks."

for i in {1..100}; do
  # Generate a random IP address
  ip=$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))
  echo "Scanning $ip:22..."
  # nc (netcat) with 1 sec timeout
  nc -z -w 1 $ip 22 &
done

wait
echo "[+] Scan complete."
