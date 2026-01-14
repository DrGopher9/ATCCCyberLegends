#!/bin/bash

# Check if the script is being run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root."
  exit 1
fi

# Install ufw if not already installed
if ! command -v ufw &>/dev/null; then
  apt-get update
  apt-get install -y ufw
fi

# Enable the firewall
#ufw enable

# Allow SSH (replace 22 with your actual SSH port if changed)
#ufw allow 22/tcp

# Allow essential services (adjust as needed)
#ufw allow 80/tcp    # HTTP
#ufw allow 443/tcp   # HTTPS

# Block common attack ports
ufw deny 23         # Telnet
ufw deny 135        # MS RPC
ufw deny 137/udp    # NetBIOS Name Service
ufw deny 138/udp    # NetBIOS Datagram Service
ufw deny 139        # NetBIOS Session Service
ufw deny 445        # Microsoft-DS (SMB)

# Show current firewall status
ufw status

echo "Firewall configuration completed."
