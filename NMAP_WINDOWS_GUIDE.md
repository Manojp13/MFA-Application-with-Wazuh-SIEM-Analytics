# Guide to Using Nmap on Windows to Scan Your Network

## Step 1: Download and Install Nmap

1. Go to the official Nmap download page: https://nmap.org/download.html
2. Download the Windows installer (usually named `nmap-<version>-setup.exe`).
3. Run the installer and follow the prompts to install Nmap and Zenmap (GUI).

---

## Step 2: Open Command Prompt

- Press `Win + R`, type `cmd`, and press Enter.

---

## Step 3: Run a Network Scan

- To scan your local subnet (replace `192.168.123.0/24` with your subnet):

```
nmap -sP 192.168.123.0/24
```

- This will list all active devices on your network.

---

## Step 4: Identify Your Router

- Look for the device with the manufacturer name matching your router brand or the device with the IP address that is likely the gateway.

---

## Step 5: Scan for Open Ports on Suspected Router IP

- Once you identify a candidate IP, scan for open ports (e.g., port 80 for HTTP):

```
nmap -p 80 <IP_ADDRESS>
```

- If port 80 is open, you can try accessing `http://<IP_ADDRESS>` in your browser.

---

## Additional Tips

- You can also use Zenmap (the GUI) for easier scanning.
- If you need help interpreting the scan results, save the output and share it.

---

This completes the guide to scanning your network with Nmap on Windows.
