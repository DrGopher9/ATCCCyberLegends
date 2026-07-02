================================================================================
CCDC SPLUNK UNIVERSAL FORWARDER DEPLOYMENT
================================================================================

SCRIPTS
================================================================================

deploy-forwarder-linux.sh     - Deploy forwarder on Ubuntu/Fedora/CentOS
Deploy-Forwarder-Windows.ps1  - Deploy forwarder on Windows Server

================================================================================
PREREQUISITES
================================================================================

1. Download Universal Forwarder from:
   https://www.splunk.com/en_us/download/universal-forwarder.html

2. Ensure receiving port (9997) is open on the Splunk indexer:
   - Splunk Web > Settings > Forwarding and receiving > Configure receiving
   - Add port 9997

3. Firewall rules allow traffic from forwarder to indexer on port 9997

================================================================================
QUICK DEPLOYMENT
================================================================================

LINUX:
  chmod +x deploy-forwarder-linux.sh
  ./deploy-forwarder-linux.sh

WINDOWS (PowerShell as Admin):
  .\Deploy-Forwarder-Windows.ps1

================================================================================
MANUAL INSTALLATION
================================================================================

LINUX:
  # Extract
  tar -xzf splunkforwarder-*.tgz -C /opt/

  # Configure outputs
  cat > /opt/splunkforwarder/etc/system/local/outputs.conf << EOF
  [tcpout]
  defaultGroup = default-autolb-group

  [tcpout:default-autolb-group]
  server = INDEXER_IP:9997
  EOF

  # Start and accept license
  /opt/splunkforwarder/bin/splunk start --accept-license
  /opt/splunkforwarder/bin/splunk enable boot-start

WINDOWS:
  # Run MSI installer
  msiexec /i splunkforwarder.msi RECEIVING_INDEXER="INDEXER_IP:9997" AGREETOLICENSE=yes /quiet

================================================================================
MONITORED LOGS BY DEFAULT
================================================================================

LINUX:
  /var/log/syslog
  /var/log/messages
  /var/log/auth.log
  /var/log/secure
  /var/log/audit/audit.log
  /var/log/apache2/*.log
  /var/log/httpd/*.log
  /var/log/nginx/*.log
  /var/log/mysql/*.log
  /var/log/mail.log

WINDOWS:
  Windows Security Event Log
  Windows Application Event Log
  Windows System Event Log
  PowerShell Operational Log
  Sysmon (if installed)
  DNS Server Log (if DC)
  DHCP Server Log (if DHCP)

================================================================================
VERIFY FORWARDING
================================================================================

On Forwarder:
  # Linux
  /opt/splunkforwarder/bin/splunk list forward-server

  # Windows
  & "C:\Program Files\SplunkUniversalForwarder\bin\splunk.exe" list forward-server

On Indexer (Splunk Web):
  Search: index=* host=HOSTNAME | head 10

================================================================================
COMMON ISSUES
================================================================================

1. "Connection refused" to indexer:
   - Check firewall on indexer (port 9997)
   - Verify receiving is enabled in Splunk

2. Forwarder not starting:
   - Check /opt/splunkforwarder/var/log/splunk/splunkd.log
   - Verify permissions: chown -R splunk:splunk /opt/splunkforwarder

3. Logs not appearing:
   - Check inputs.conf paths match actual log locations
   - Verify log files have read permissions
   - Check index exists on indexer

================================================================================
ADD CUSTOM LOG SOURCES
================================================================================

Edit inputs.conf:

  [monitor:///path/to/logfile.log]
  disabled = false
  index = main
  sourcetype = custom_log

Restart forwarder:
  /opt/splunkforwarder/bin/splunk restart

================================================================================
