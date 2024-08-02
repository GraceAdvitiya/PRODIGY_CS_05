# PRODIGY_CS_05

Welcome to PRODIGY_CS_05! This is a project that aims to capture and analyse network packets and displays relevant information such as IP adddresses, protocols and payload data. 

## Function
Here is a concise 5-step algorithm for using a packet sniffer tool to troubleshoot network issues:

1. Setup: Configure the packet sniffer to capture relevant traffic on the network.
2. Capture: Run the packet sniffer during the period when the issue occurs.
3. Filter: Apply filters to isolate packets related to the suspected problem (e.g., specific protocols or IP addresses).
4. Analyze: Examine captured packets for patterns or anomalies indicating the source of the issue.
5. Report: Document findings and suggest actions to resolve the network issue.


## Usage

Here's how you might use your packet sniffer tool in a real-world scenario to troubleshoot network latency issues:

Identify the Issue: Users report slow network performance.
Set Up the Sniffer: Configure your packet sniffer to capture TCP traffic on the affected subnet.
Capture Traffic: Run the sniffer during peak usage times to capture relevant traffic.
Analyze Data: Look for patterns such as high retransmission rates, excessive packet loss, or specific devices consuming large amounts of bandwidth.
Report Findings: Document your findings and provide recommendations, such as adjusting network configurations or upgrading hardware.
Implement Changes: Make the necessary changes based on your analysis and monitor the network to ensure performance improves.

## Implementation 
```
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Define the log file
log_file = "packet_log.txt"

def log_packet_info(info):
    # Log packet info to console
    print(info)
    # Log packet info to file
    with open(log_file, "a") as f:
        f.write(info + "\n")

def packet_callback(packet):
    # Basic packet info
    source_ip = packet[IP].src
    dest_ip = packet[IP].dst
    protocol = packet[IP].proto

    # Protocol type
    if protocol == 6:
        protocol_name = "TCP"
    elif protocol == 17:
        protocol_name = "UDP"
    elif protocol == 1:
        protocol_name = "ICMP"
    else:
        protocol_name = "Other"

    packet_info = (
        f"Source IP: {source_ip}\n"
        f"Destination IP: {dest_ip}\n"
        f"Protocol: {protocol_name}\n"
    )

    # Payload data
    if protocol == 6:  # TCP
        payload = packet[TCP].payload
    elif protocol == 17:  # UDP
        payload = packet[UDP].payload
    elif protocol == 1:  # ICMP
        payload = packet[ICMP].payload
    else:
        payload = None

    if payload:
        packet_info += f"Payload: {payload}\n"
    packet_info += "=" * 50

    # Log packet info
    log_packet_info(packet_info)

# Sniffing the packets
def start_sniffer():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffer()
```

## Output

![Screenshot (503)](https://github.com/user-attachments/assets/2f982611-1d06-4a9e-8e6d-e23d0501016d)


Happy coding!
