================================================================================
CCDC SPLUNK DASHBOARDS
================================================================================

DASHBOARDS INCLUDED
================================================================================

1. ccdc_security_overview.xml
   - Main security overview dashboard
   - Failed/successful login summary
   - Event counts by host
   - Authentication timeline

2. ccdc_windows_security.xml
   - Windows-specific security monitoring
   - AD failed logins and lockouts
   - User/group changes
   - Privileged logons
   - Scheduled tasks and services
   - PowerShell activity

3. ccdc_linux_security.xml
   - Linux server security monitoring
   - SSH authentication events
   - Sudo activity
   - Cron jobs
   - Audit log events

4. ccdc_web_monitoring.xml
   - Web server monitoring
   - Request counts and errors
   - Attack pattern detection
   - Suspicious user agents
   - POST request tracking

================================================================================
INSTALLATION
================================================================================

METHOD 1: Via Splunk Web UI

1. Log in to Splunk Web as admin
2. Go to Settings > Knowledge > User interface > Views
3. Click "New Dashboard"
4. Choose "Dashboard XML Editor"
5. Paste the XML content
6. Save the dashboard

METHOD 2: File Copy

1. Copy XML files to:
   Linux:   $SPLUNK_HOME/etc/apps/search/local/data/ui/views/
   Windows: %SPLUNK_HOME%\etc\apps\search\local\data\ui\views\

2. Set permissions:
   chown splunk:splunk *.xml
   chmod 644 *.xml

3. Restart Splunk or refresh:
   $SPLUNK_HOME/bin/splunk restart
   OR
   Settings > Server Controls > Restart Splunk

METHOD 3: Create as App

1. Create directory structure:
   $SPLUNK_HOME/etc/apps/ccdc_dashboards/
   $SPLUNK_HOME/etc/apps/ccdc_dashboards/default/
   $SPLUNK_HOME/etc/apps/ccdc_dashboards/default/data/ui/views/

2. Create app.conf:
   $SPLUNK_HOME/etc/apps/ccdc_dashboards/default/app.conf

   [install]
   state = enabled

   [ui]
   is_visible = true
   label = CCDC Dashboards

   [launcher]
   author = CCDC Blue Team
   description = Security monitoring dashboards for CCDC
   version = 1.0.0

3. Copy XML files to views directory

4. Restart Splunk

================================================================================
PREREQUISITES
================================================================================

For dashboards to show data, you need:

1. Universal Forwarders deployed on all systems
2. Forwarders configured to send to indexer port 9997
3. Correct sourcetypes configured:
   - linux_secure (Linux auth logs)
   - syslog (Linux system logs)
   - linux_audit (Linux audit logs)
   - WinEventLog:Security (Windows Security logs)
   - WinEventLog:System (Windows System logs)
   - WinEventLog:*PowerShell* (PowerShell logs)
   - access_combined (Apache access logs)
   - apache_error (Apache error logs)

================================================================================
USEFUL SEARCHES
================================================================================

# All failed logins
index=* ("Failed password" OR "authentication failure" OR EventCode=4625)

# Successful logins
index=* ("Accepted" OR EventCode=4624)

# New user created (Windows)
index=* EventCode=4720

# Admin group changes (Windows)
index=* (EventCode=4728 OR EventCode=4732)

# Sudo activity (Linux)
index=* sudo

# Web attack patterns
index=* sourcetype=access_* | where match(uri, "(?i)\.\.\/|union.*select|<script>")

# Host status
| metadata type=hosts index=* | eval age=now()-lastTime | table host, lastTime, age

================================================================================
CUSTOMIZATION
================================================================================

To modify searches:

1. Edit the XML file
2. Find the <query> tag
3. Modify the SPL search
4. Save and refresh

To change time ranges:

1. Find <earliest> and <latest> tags
2. Modify values:
   -1h  = last 1 hour
   -4h  = last 4 hours
   -24h = last 24 hours
   -7d  = last 7 days

================================================================================
TROUBLESHOOTING
================================================================================

No data showing:
- Verify forwarders are connected: Search "index=* | stats count by host"
- Check time range
- Verify sourcetype: Search "index=* | stats count by sourcetype"

Dashboard not appearing:
- Check file permissions
- Verify XML syntax (no unclosed tags)
- Check splunkd.log for errors
- Restart Splunk

Searches slow:
- Add "earliest=-1h" to limit time range
- Use more specific index names
- Consider summary indexing for frequently used searches

================================================================================
