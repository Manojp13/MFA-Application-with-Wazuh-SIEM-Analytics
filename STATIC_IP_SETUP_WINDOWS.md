# How to Set a Static IP Address on Windows

## Overview
Setting a static IP address on your Windows machine ensures that the IP does not change, which is important for stable network services like Wazuh agent communication with the manager.

---

## Steps to Set a Static IP Address

1. **Open Network Connections**
   - Press `Win + R`, type `ncpa.cpl`, and press Enter.
   - This opens the Network Connections window.

2. **Select Your Network Adapter**
   - Right-click on the active network adapter (e.g., Ethernet or Wi-Fi) and select `Properties`.

3. **Open IPv4 Properties**
   - In the list, select `Internet Protocol Version 4 (TCP/IPv4)` and click `Properties`.

4. **Set Static IP**
   - Select `Use the following IP address`.
   - Enter the desired IP address (e.g., `192.168.50.100`).
   - Enter the Subnet mask (usually `255.255.255.0`).
   - Enter the Default gateway (e.g., `192.168.50.1`).

5. **Set DNS Servers**
   - Select `Use the following DNS server addresses`.
   - Enter preferred DNS server (e.g., `8.8.8.8`).
   - Enter alternate DNS server (e.g., `8.8.4.4`).

6. **Save Settings**
   - Click `OK` to close the IPv4 properties.
   - Click `Close` to close the adapter properties.

7. **Verify Static IP**
   - Open Command Prompt and run:
     ```
     ipconfig
     ```
   - Confirm the IP address matches the static IP you set.

---

## Additional Notes

- Ensure the static IP you choose is outside the DHCP range of your router to avoid IP conflicts.
- You may need administrative privileges to change network settings.
- Restart your network adapter or computer if necessary.

---

This completes the static IP setup on Windows.
