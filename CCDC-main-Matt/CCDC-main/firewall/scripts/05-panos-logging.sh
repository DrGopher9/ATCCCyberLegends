#!/bin/bash
###############################################################################
# 05-panos-logging.sh - Logging and SIEM Integration
# Target: Palo Alto VM (PAN-OS 11.x)
# Purpose: Configure logging to Splunk SIEM for visibility
###############################################################################

cat << 'LOGGING_COMMANDS'
================================================================================
PALO ALTO LOGGING AND SIEM INTEGRATION
Run these commands in PAN-OS CLI (configuration mode)
================================================================================

According to topology, Splunk SIEM is on the Public network (172.20.241.x)

#=============================================================================
# STEP 1: CHECK CURRENT LOGGING STATUS
#=============================================================================

# Operational mode
show logging-status

# Show log statistics
show log-statistics

# Show current syslog configuration
show config running | match syslog

#=============================================================================
# STEP 2: CONFIGURE SYSLOG SERVER (SPLUNK)
#=============================================================================

configure

# Create syslog server profile for Splunk
# Adjust IP to your Splunk server
set shared log-settings syslog splunk-siem server splunk-server server <SPLUNK-IP>
set shared log-settings syslog splunk-siem server splunk-server port 514
set shared log-settings syslog splunk-siem server splunk-server transport UDP
set shared log-settings syslog splunk-siem server splunk-server format BSD
set shared log-settings syslog splunk-siem server splunk-server facility LOG_USER

# For Splunk HEC (HTTP Event Collector) - if using HTTPS
# set shared log-settings syslog splunk-hec server splunk-hec-server server <SPLUNK-IP>
# set shared log-settings syslog splunk-hec server splunk-hec-server port 8088
# set shared log-settings syslog splunk-hec server splunk-hec-server transport SSL

#=============================================================================
# STEP 3: CONFIGURE LOG FORWARDING PROFILE
#=============================================================================

# Create log forwarding profile for security logs
set shared log-settings profiles ccdc-logging match-list security-logs log-type traffic
set shared log-settings profiles ccdc-logging match-list security-logs filter "All Logs"
set shared log-settings profiles ccdc-logging match-list security-logs send-syslog splunk-siem

set shared log-settings profiles ccdc-logging match-list threat-logs log-type threat
set shared log-settings profiles ccdc-logging match-list threat-logs filter "All Logs"
set shared log-settings profiles ccdc-logging match-list threat-logs send-syslog splunk-siem

set shared log-settings profiles ccdc-logging match-list url-logs log-type url
set shared log-settings profiles ccdc-logging match-list url-logs filter "All Logs"
set shared log-settings profiles ccdc-logging match-list url-logs send-syslog splunk-siem

set shared log-settings profiles ccdc-logging match-list auth-logs log-type auth
set shared log-settings profiles ccdc-logging match-list auth-logs filter "All Logs"
set shared log-settings profiles ccdc-logging match-list auth-logs send-syslog splunk-siem

#=============================================================================
# STEP 4: APPLY LOG FORWARDING TO SECURITY RULES
#=============================================================================

# Apply log forwarding profile to all security rules
set rulebase security rules allow-scoring-engine log-setting ccdc-logging
set rulebase security rules allow-web-public log-setting ccdc-logging
set rulebase security rules allow-smtp-public log-setting ccdc-logging
set rulebase security rules deny-all log-setting ccdc-logging

# Or apply to all rules at once (in Web GUI):
# Policies > Security > Select all rules > Actions > Log Forwarding

#=============================================================================
# STEP 5: CONFIGURE SYSTEM LOGGING
#=============================================================================

# Log system events to syslog
set shared log-settings system match-list system-critical log-type system
set shared log-settings system match-list system-critical filter "(severity eq critical)"
set shared log-settings system match-list system-critical send-syslog splunk-siem

set shared log-settings system match-list system-high log-type system
set shared log-settings system match-list system-high filter "(severity eq high)"
set shared log-settings system match-list system-high send-syslog splunk-siem

# Log configuration changes
set shared log-settings config match-list config-logs log-type config
set shared log-settings config match-list config-logs filter "All Logs"
set shared log-settings config match-list config-logs send-syslog splunk-siem

#=============================================================================
# STEP 6: ENABLE ENHANCED LOGGING OPTIONS
#=============================================================================

# Enable extended packet capture for threats
set deviceconfig setting logging enhanced-application-logging yes

# Log URL details
set deviceconfig setting logging log-url-full yes

# Log X-Forwarded-For header (for proxied connections)
set deviceconfig setting logging log-xff yes

#=============================================================================
# STEP 7: CONFIGURE LOCAL LOGGING
#=============================================================================

# Ensure local logging is enabled (for on-box analysis)
set deviceconfig setting logging traffic-log yes
set deviceconfig setting logging threat-log yes
set deviceconfig setting logging config-log yes
set deviceconfig setting logging system-log yes
set deviceconfig setting logging url-log yes

#=============================================================================
# STEP 8: SET LOG RETENTION
#=============================================================================

# Set disk quota for logs (adjust based on disk space)
set deviceconfig setting logging logging-service traffic quota 4096
set deviceconfig setting logging logging-service threat quota 1024
set deviceconfig setting logging logging-service config quota 256
set deviceconfig setting logging logging-service system quota 256

#=============================================================================
# STEP 9: COMMIT AND VERIFY
#=============================================================================

# Commit
commit

# Verify syslog configuration (operational mode)
exit
show logging-status

# Test syslog connectivity
test logging syslog-connectivity

# Check log forwarding status
show log-forwarding-status

#=============================================================================
# STEP 10: VERIFY ON SPLUNK
#=============================================================================

# On Splunk, search for Palo Alto logs:
# index=* sourcetype="pan:*"
# or
# index=* host=<firewall-ip>

# Common Splunk searches for PA logs:
# index=* sourcetype="pan:traffic" action=deny
# index=* sourcetype="pan:threat"
# index=* sourcetype="pan:system"

LOGGING_COMMANDS

echo ""
echo "============================================"
echo "LOGGING CONFIGURATION CHECKLIST"
echo "============================================"
echo ""
echo "[ ] Configure syslog server profile for Splunk"
echo "[ ] Create log forwarding profile"
echo "[ ] Apply log forwarding to security rules"
echo "[ ] Configure system log forwarding"
echo "[ ] Enable enhanced logging options"
echo "[ ] Set appropriate log retention"
echo "[ ] Test syslog connectivity"
echo "[ ] Verify logs appear in Splunk"
echo ""
echo "SPLUNK VERIFICATION:"
echo "Search: index=* sourcetype=\"pan:*\""
echo ""
