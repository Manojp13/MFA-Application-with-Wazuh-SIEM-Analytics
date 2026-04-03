# Wazuh Integration Guide for Flask App on Windows

## Overview
This guide explains how to install and configure the Wazuh agent on a Windows machine running the Flask app, and how to configure the Wazuh manager to receive and analyze the Flask app logs.

---

## 1. Install Wazuh Agent on Windows

1. Download the latest Wazuh agent for Windows from the official site:
   https://wazuh.com/downloads/

2. Run the installer and follow the prompts.

3. During installation, configure the agent to connect to your Wazuh manager IP address and port (default 1514).

4. Complete the installation and start the Wazuh agent service.

---

## 2. Configure Wazuh Agent to Monitor Flask Logs

1. Locate the Wazuh agent configuration file `ossec.conf` (usually in `C:\Program Files (x86)\ossec-agent\`).

2. Edit `ossec.conf` to add a localfile entry to monitor the Flask app log file:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>C:\path\to\your\flask\app\logs\2fa_flask.log</location>
</localfile>
```

Replace `C:\path\to\your\flask\app\logs\2fa_flask.log` with the actual path to your Flask app log file.

3. Save the file and restart the Wazuh agent service.

---

## 3. Configure Wazuh Manager to Receive Logs

1. Ensure the Wazuh manager is configured to accept logs from the agent.

2. Verify the agent is registered and connected in the Wazuh manager dashboard.

3. Configure rules and decoders if needed to parse the Flask app logs properly.

---

## 4. Verify Integration

1. Generate some logs from your Flask app by accessing the app or triggering log events.

2. Check the Wazuh manager dashboard for incoming logs from the agent.

3. Use the Wazuh Kibana plugin or other tools to analyze the logs.

---

## Additional Notes

- Ensure network connectivity between the Windows machine and the Wazuh manager.

- Adjust firewall settings if necessary to allow communication on the required ports.

- Customize log rotation and retention policies as needed.

---

This completes the Wazuh integration setup for your Flask app on Windows.
