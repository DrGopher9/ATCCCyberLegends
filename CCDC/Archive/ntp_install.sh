#!/bin/bash

# Script to configure Debian as an NTP server using Chrony

# Check if the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root or with sudo."
  exit 1
fi

echo "Updating package lists..."
apt update

echo "Installing Chrony (NTP server)..."
apt install -y chrony

# Backup the default Chrony configuration
CHRONY_CONF="/etc/chrony/chrony.conf"
BACKUP_CONF="${CHRONY_CONF}.bak"
if [ ! -f "$BACKUP_CONF" ]; then
  echo "Backing up original Chrony configuration to $BACKUP_CONF..."
  cp "$CHRONY_CONF" "$BACKUP_CONF"
fi

echo "Configuring Chrony to act as an NTP server..."

# Modify the configuration file
cat <<EOF > "$CHRONY_CONF"
# Chrony configuration for NTP server

# Allow access to clients on the network (replace subnet with your network)
allow 192.168.1.0/24

# Use online NTP servers as upstream sources
pool ntp.ubuntu.com iburst
pool 0.debian.pool.ntp.org iburst
pool 1.debian.pool.ntp.org iburst
pool 2.debian.pool.ntp.org iburst
pool 3.debian.pool.ntp.org iburst

# Enable logging for troubleshooting
log measurements statistics tracking

# Save drift file to maintain clock accuracy between reboots
driftfile /var/lib/chrony/chrony.drift

# Enable hardware timestamping for more accurate time (optional)
hwclockfile /etc/adjtime

# Serve time to NTP clients
local stratum 10
EOF

echo "Restarting Chrony service to apply changes..."
systemctl restart chrony

# Enable the service to start at boot
echo "Enabling Chrony service on startup..."
systemctl enable chrony

echo "Verifying NTP server configuration..."
chronyc sources

echo "NTP server setup complete. The server is ready to serve time to clients on the 192.168.1.0/24 subnet."
