# How to Set a Static IP Address on Amazon Linux (Wazuh Manager VM)

## Overview
This guide explains how to assign a static IP address to your Wazuh manager running on an Amazon Linux VM in VMware.

---

## Step 1: Identify Network Interface

Run the following command to list network interfaces:
```
ip addr
```
Note the interface name (e.g., `eth0` or `ens33`).

---

## Step 2: Backup Current Network Configuration

Backup the current network config file:
```
sudo cp /etc/sysconfig/network-scripts/ifcfg-eth0 /etc/sysconfig/network-scripts/ifcfg-eth0.bak
```
Replace `eth0` with your interface name.

---

## Step 3: Edit Network Configuration

Edit the network config file:
```
sudo vi /etc/sysconfig/network-scripts/ifcfg-eth0
```

Modify or add the following lines:
```
BOOTPROTO=static
ONBOOT=yes
IPADDR=192.168.28.164
NETMASK=255.255.255.0
GATEWAY=192.168.28.1
DNS1=8.8.8.8
DNS2=8.8.4.4
```
Replace IPADDR, NETMASK, GATEWAY, and DNS with values suitable for your network.

---

## Step 4: Restart Network Service

Restart the network service to apply changes:
```
sudo systemctl restart network
```

---

## Step 5: Verify Static IP

Check the IP address:
```
ip addr show eth0
```
Confirm the IP matches the static IP you set.

---

## Additional Notes

- Ensure the static IP is outside your DHCP range to avoid conflicts.
- If using VMware NAT or Bridged networking, configure accordingly.
- You may need to update firewall rules if applicable.

---

This completes the static IP setup for your Wazuh manager on Amazon Linux.
