#!/bin/bash
#
# DPI System - iptables Setup Script
# This script configures iptables to route traffic through NFQUEUE
#

echo "======================================"
echo "DPI System - iptables Setup"
echo "======================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

echo "[1/4] Flushing existing iptables rules..."
iptables -F
iptables -X

echo "[2/4] Setting up NFQUEUE rules..."
# Route traffic to NFQUEUE 0 for DPI analysis
iptables -A INPUT -j NFQUEUE --queue-num 0
iptables -A OUTPUT -j NFQUEUE --queue-num 0
iptables -A FORWARD -j NFQUEUE --queue-num 0

echo "[3/4] Verifying iptables configuration..."
iptables -L -n -v | grep NFQUEUE

echo "[4/4] Setup complete!"
echo ""
echo "======================================"
echo "Important Notes:"
echo "======================================"
echo "1. NFQUEUE rules are now active"
echo "2. Run the DPI System with: sudo python main.py"
echo "3. To remove rules: sudo iptables -F"
echo "4. These rules will be lost on reboot"
echo "5. To persist: sudo iptables-save > /etc/iptables/rules.v4"
echo ""
echo "Setup completed successfully!"
