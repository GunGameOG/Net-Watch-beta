#!/bin/bash

# Webhook URL for Discord notifications
WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-url"

# Set interface to monitor (e.g., eth0, wlan0)
INTERFACE="eth0"

# Thresholds for DDoS detection
PACKET_THRESHOLD=10000  # Packets per second
BANDWIDTH_THRESHOLD=1000 # Mbps

# File to save the pcap
PCAP_FILE="/tmp/ddos_$(date +%s).pcap"

# Sampling interval in seconds (adjust to reduce CPU usage)
SAMPLE_INTERVAL=10

# Function to send notification to Discord
send_discord_notification() {
    local message=$1
    curl -H "Content-Type: application/json" -X POST -d "{\"content\": \"$message\"}" $WEBHOOK_URL
}

# Function to monitor traffic and detect DDoS
monitor_traffic() {
    echo "Starting traffic monitoring on $INTERFACE..."
    
    while true; do
        # Capture traffic for a short duration
        tshark -i $INTERFACE -a duration:$SAMPLE_INTERVAL -q -w $PCAP_FILE -z io,stat,1 2>/dev/null | \
        while read -r line; do
            # Extract relevant statistics
            current_time=$(date +"%Y-%m-%d %H:%M:%S")
            pps=$(echo $line | awk '{print $6}') # Packets per second
            mbps=$(echo $line | awk '{print $8}') # Mbps
            protocol=$(echo $line | awk '{print $2}') # Protocol
            src_ip=$(echo $line | awk '{print $4}') # Source IP
            dst_ip=$(echo $line | awk '{print $5}') # Destination IP
            src_port=$(echo $line | awk '{print $7}') # Source Port
            dst_port=$(echo $line | awk '{print $9}') # Destination Port
            
            # Check if thresholds are exceeded
            if (( $(echo "$pps > $PACKET_THRESHOLD" | bc -l) )) && \
               (( $(echo "$mbps > $BANDWIDTH_THRESHOLD" | bc -l) )); then
                echo "DDoS attack detected at $current_time!"
                message="**DDoS Attack Detected!**\nTime: $current_time\nSource IP: $src_ip\nSource Port: $src_port\nDestination IP: $dst_ip\nDestination Port: $dst_port\nProtocol: $protocol\nPackets per second: $pps\nBandwidth: $mbps Mbps"
                send_discord_notification "$message"
            fi
        done
        
        # Sleep for the sampling interval before next capture
        sleep $SAMPLE_INTERVAL
    done
}

# Function to check if the attack has stopped
check_attack_stopped() {
    echo "Checking if attack has stopped..."
    sleep 10
    pps=$(tshark -i $INTERFACE -c 10 -q -z io,stat,1 | awk '{print $6}')
    if (( $(echo "$pps < $PACKET_THRESHOLD" | bc -l) )); then
        current_time=$(date +"%Y-%m-%d %H:%M:%S")
        echo "DDoS attack stopped at $current_time."
        message="**DDoS Attack Stopped**\nTime: $current_time\nPackets per second: $pps"
        send_discord_notification "$message"
    fi
}

# Main loop
while true; do
    monitor_traffic
    check_attack_stopped
done
