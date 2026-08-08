# Custom Wazuh SOAR Pipeline: Direct JSON Ingestion & Automated Remediation

## Overview
This repository contains a custom Security Orchestration, Automation, and Response (SOAR) daemon engineered to bypass limitations within the native Wazuh Active Response engine. The script directly ingests raw SIEM logs, utilizes regular expressions to extract attacker IPs from malformed syslog entries, and automates non-interactive firewall blocks at the network layer.

## Architecture
* **Attacker:** Kali Linux (Hydra FTP Brute-force)
* **Target:** Metasploitable 2 (vsftpd)
* **SIEM:** Wazuh Manager (Dockerized)
* **Automation:** Custom Bash Systemd Daemon

## The Problem: Native Decoder Failure
The Wazuh Manager was initially configured to utilize its native Active Response engine to trigger a firewall block upon detecting FTP brute-force attacks (Rule `2501`). The standard configuration was applied within `ossec.conf` (see `ossec.conf.snippet`). 

Despite correct environmental configuration, the native `execd` daemon failed to execute the response block. Investigation into the raw `alerts.json` output revealed that Wazuh's internal decoders failed to properly parse the `srcip` field from the agentless syslog output. Because the IP was embedded inside the `full_log` string rather than explicitly defined as a source IP, the Active Response engine silently aborted the remediation action to prevent erroneous blocking.

## The Engineered Solution
Rather than relying on the broken internal decoder, I engineered a custom Linux daemon (`soar-runner.sh`) to act as an independent SOAR platform. 

The daemon performs the following automated sequence:
1. **Direct Ingestion:** Bypasses `execd` by attaching directly to the Wazuh Docker container and tailing the raw `alerts.json` stream in real-time.
2. **Regex Extraction:** Filters for the specific rule ID (`2501`) and uses advanced `grep` regular expressions to surgically extract the attacker IP from the raw `full_log` string (`rhost=x.x.x.x`).
3. **Automated Remediation:** Establishes a non-interactive, key-based SSH connection to the target machine and executes a `sudo iptables` drop rule, killing the attacker's connection at the network layer before further authentication attempts can occur.
4. **State Management:** Utilizes amnesia flags (`tail -n 0`) upon service restarts to prevent redundant blocking of historical alerts.

The pipeline runs persistently as a systemd service (`wazuh-soar.service`) to ensure high availability and automatic restarts upon failure.

## Diagnostic & Troubleshooting Process
To isolate the silent failure within the SIEM container, the following diagnostic commands were used to verify raw ingestion and test JSON parsing on the host:

**Tailing the raw alerts stream for Rule 2501:**
`docker exec single-node-wazuh.manager-1 tail -n 50 /var/ossec/logs/alerts/alerts.json | grep '"id":"2501"'`

**Testing jq field extraction (which confirmed the missing `srcip` key):**
`docker exec single-node-wazuh.manager-1 tail -n 100 /var/ossec/logs/alerts/alerts.json | jq -r 'select(.rule.id=="2501") | .data.srcip // .srcip'`

**Monitoring the custom daemon output during live fire:**
`sudo journalctl -u wazuh-soar -f`

## Manual Testing & Validation Commands
The SSH execution pipeline was validated using the following commands to ensure proper certificate authentication and firewall state management on the remote target (`192.168.86.183`):

**Apply Firewall Block (Append):**
`ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no msfadmin@192.168.86.183 "echo msfadmin | sudo -S iptables -A INPUT -s <IP> -j DROP"`

**Remove Firewall Block (Delete):**
`ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no msfadmin@192.168.86.183 "echo msfadmin | sudo -S iptables -D INPUT -s <IP> -j DROP"`

**Inspect Current IPTables Rules:**
`ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no msfadmin@192.168.86.183 "echo msfadmin | sudo -S iptables -L INPUT -n -v"`
