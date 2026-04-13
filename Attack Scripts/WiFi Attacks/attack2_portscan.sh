#!/bin/bash

################################################################################
# PORT SCAN ATTACK SIMULATION - POWERFUL VERSION
################################################################################
# Simulates a rapid SYN port scanning attack to test Module 3 detection
# Uses Nmap for realistic Stealth Scan (-sS)
################################################################################

echo "════════════════════════════════════════════════════════════════════════════════"
echo "🔍 PORT SCAN ATTACK SIMULATION (Powerful Mode)"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "This script uses NMAP to perform a rapid SYN Stealth Scan."
echo "TARGET: 100 Ports (1-100)"
echo ""

# Configuration
TARGET="127.0.0.1"

echo "Target: $TARGET"
echo "Ports to scan: Range 1-100"
echo "Mode: SYN Stealth Scan (-sS)"
echo ""
read -p "Press ENTER to start powerful port scan..."
echo ""

echo "🚀 Launching Nmap SYN Scan..."

# Check for sudo/root
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo) for SYN scan"
  exit
fi

# Run Nmap
# -sS: TCP SYN (Stealth) Scan
# -p 1-100: Top 100 ports
# -T4: Aggressive timing (Faster)
# --open: Only show open ports
nmap -sS -p 1-100 -T4 $TARGET

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "✅ PORT SCAN COMPLETED"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""
echo "Expected Detection:"
echo "  • Module 3 should show PORT_SCAN alerts (>20 ports accessing)"
echo "  • Module 4 should detect Port Scan Attack"
echo ""
echo "Check Module 4 Dashboard: http://localhost:8000/module4"
echo ""
