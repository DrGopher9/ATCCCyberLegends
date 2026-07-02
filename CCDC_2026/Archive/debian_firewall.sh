#!/bin/bash

# Ensure script is run with root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run the script as root."
    exit 1
fi

# Close common ports
ufw default deny incoming
ufw default allow outgoing

# Allow essential ports
#ufw allow ssh
ufw allow 53/udp   # DNS
ufw allow 123/udp  # NTP
ufw allow 514/udp  # Splunk

# Additional rules based on your specific requirements
# ufw allow <port>/<protocol>
# Example: ufw allow 8080/tcp

# Enable firewall
ufw enable

# Display firewall status
ufw status
