#!/bin/bash
echo "Direct SIEM ingestion started. Monitoring for new Rule 2501 alerts only..."

# Stream alerts directly from the SIEM container, ignoring old entries
docker exec single-node-wazuh.manager-1 tail -F -n 0 /var/ossec/logs/alerts/alerts.json | grep --line-buffered -E '"id"\s*:\s*"2501"' | while read -r line; do

    # Extract the IP address located immediately after 'rhost=' or 'rhost-'
    IP=$(echo "$line" | grep -o -E 'rhost[=-][0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')

    if [ -n "$IP" ]; then
        echo "[SOAR Triggered] Extracted Attacker IP: $IP"
        
        # Execute non-interactive SSH to drop the IP at the network layer on the target machine
        ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedAlgorithms=+ssh-rsa -i /home/jtdawgzone/.ssh/id_rsa -o StrictHostKeyChecking=no msfadmin@192.168.86.183 "echo msfadmin | sudo -S iptables -A INPUT -s $IP -j DROP"
        
        echo "[SOAR Triggered] Rule applied to Metasploitable."
    fi
done