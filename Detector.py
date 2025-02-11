from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from collections import defaultdict
import time
import logging

# Set up logging
logging.basicConfig(
    filename="attack_detector.log",
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Thresholds
REQUEST_THRESHOLD = 100  # Number of requests per time window to trigger warning
TIME_WINDOW = 10         # Time window in seconds to analyze traffic
COOLDOWN_PERIOD = 60     # Time in seconds to avoid spamming alerts for the same IP

# Tracking traffic and alerts
traffic_data = defaultdict(list)
alert_timestamps = defaultdict(lambda: 0)

# Attack Detection Counters
syn_flood_counter = defaultdict(int)
udp_flood_counter = defaultdict(int)
icmp_flood_counter = defaultdict(int)
http_flood_counter = defaultdict(int)

def detect_attack(pkt):
    """Callback function to process each captured packet."""
    global syn_flood_counter, udp_flood_counter, icmp_flood_counter, http_flood_counter
    if IP in pkt:
        src_ip = pkt[IP].src  # Source IP address
        current_time = time.time()

        # Track the timestamps of requests from each IP
        traffic_data[src_ip].append(current_time)

        # Remove timestamps older than the time window
        traffic_data[src_ip] = [
            timestamp for timestamp in traffic_data[src_ip] if current_time - timestamp <= TIME_WINDOW
        ]

        # Analyze the type of attack based on packet characteristics
        if TCP in pkt:
            if pkt[TCP].flags == "S":  # SYN flood detection (SYN packets)
                syn_flood_counter[src_ip] += 1

        elif UDP in pkt:  # UDP flood detection (UDP packets)
            udp_flood_counter[src_ip] += 1

        elif ICMP in pkt:  # ICMP flood detection (ping packets)
            icmp_flood_counter[src_ip] += 1

        elif Raw in pkt and b"GET" in pkt[Raw].load:  # HTTP Flood detection (HTTP requests)
            http_flood_counter[src_ip] += 1

        # Check for attack type based on thresholds
        if syn_flood_counter[src_ip] > REQUEST_THRESHOLD:
            if current_time - alert_timestamps[src_ip] > COOLDOWN_PERIOD:
                logging.warning(f"Potential SYN Flood attack detected from IP: {src_ip}. Requests: {syn_flood_counter[src_ip]}")
                print(f"Alert: SYN Flood attack detected from IP: {src_ip}")
                alert_timestamps[src_ip] = current_time

        if udp_flood_counter[src_ip] > REQUEST_THRESHOLD:
            if current_time - alert_timestamps[src_ip] > COOLDOWN_PERIOD:
                logging.warning(f"Potential UDP Flood attack detected from IP: {src_ip}. Requests: {udp_flood_counter[src_ip]}")
                print(f"Alert: UDP Flood attack detected from IP: {src_ip}")
                alert_timestamps[src_ip] = current_time

        if icmp_flood_counter[src_ip] > REQUEST_THRESHOLD:
            if current_time - alert_timestamps[src_ip] > COOLDOWN_PERIOD:
                logging.warning(f"Potential ICMP Flood attack detected from IP: {src_ip}. Requests: {icmp_flood_counter[src_ip]}")
                print(f"Alert: ICMP Flood attack detected from IP: {src_ip}")
                alert_timestamps[src_ip] = current_time

        if http_flood_counter[src_ip] > REQUEST_THRESHOLD:
            if current_time - alert_timestamps[src_ip] > COOLDOWN_PERIOD:
                logging.warning(f"Potential HTTP Flood attack detected from IP: {src_ip}. Requests: {http_flood_counter[src_ip]}")
                print(f"Alert: HTTP Flood attack detected from IP: {src_ip}")
                alert_timestamps[src_ip] = current_time

def main():
    """Main function to start packet sniffing."""
    print("Starting DDoS detection...")
    logging.info("Starting DDoS detection.")
    try:
        # Sniff packets on all interfaces
        sniff(filter="ip", prn=detect_attack, store=False)
    except KeyboardInterrupt:
        print("Stopping detection.")
        logging.info("Stopped DDoS detection.")
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()
