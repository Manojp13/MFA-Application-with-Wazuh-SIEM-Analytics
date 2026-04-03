# Flask App Integration with Wazuh Monitoring

## Overview
This guide explains how to integrate your Flask application with Wazuh for centralized log monitoring and analysis.

---

## Step 1: Ensure Flask App Logging

- Your Flask app should log important events to a log file.
- In your app, logs are saved to:
  ```
  C:\Users\hp\PycharmProjects\mp\time-based-Multi-factor-auth-in-flask\logs\2fa_flask.log
  ```

---

## Step 2: Configure Wazuh Agent on Windows

1. Open the Wazuh agent configuration file `ossec.conf` (usually located at `C:\Program Files (x86)\ossec-agent\ossec.conf`).

2. Add a `<localfile>` entry to monitor the Flask app log file:
   ```xml
   <localfile>
     <log_format>syslog</log_format>
     <location>C:\Users\hp\PycharmProjects\mp\time-based-Multi-factor-auth-in-flask\logs\2fa_flask.log</location>
   </localfile>
   ```

3. Save the file with administrator privileges.

4. Restart the Wazuh agent service:
   ```
   net stop WazuhSvc
   net start WazuhSvc
   ```

---

## Step 3: Verify Agent Connection

- Ensure the Wazuh agent is registered and connected to the Wazuh manager.
- On the Wazuh manager, run:
  ```
  /var/ossec/bin/agent_control -l
  ```
- Confirm your Windows agent is listed and active.

---

## Step 4: Configure Wazuh Manager Rules and Decoders (Optional)

- To better parse and analyze Flask app logs, create custom rules and decoders in the Wazuh manager.
- Refer to Wazuh documentation for creating custom decoders and rules:
  https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax.html

---

## Step 5: Monitor Logs in Wazuh Dashboard

- Use the Wazuh Kibana plugin or other interfaces to view and analyze logs forwarded from your Flask app.
- Set up alerts based on log patterns or anomalies as needed.

---

## Additional Notes

- Ensure network connectivity and firewall rules allow communication between the Windows agent and Wazuh manager.
- Keep the Wazuh agent and manager updated for best compatibility.
- Regularly review logs and alerts to maintain security posture.

---

This completes the integration of your Flask app with Wazuh monitoring.
