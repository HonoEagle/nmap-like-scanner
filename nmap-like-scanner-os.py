import socket
import argparse
from scapy.all import *

def scan_port(host, port):
    """
    Scan a single port on a host
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set timeout to 1 second
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
        sock.close()
    except socket.error as e:
        print(f"Error scanning port {port}: {e}")

def scan_host(host, ports):
    """
    Scan a list of ports on a host
    """
    for port in ports:
        scan_port(host, port)

def os_detection(host):
    """
    Perform simple OS detection using TCP/IP stack fingerprinting
    """
    packet = IP(dst=host)/TCP(dport=80, flags="S")
    response = sr1(packet, verbose=0)
    if response:
        if response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                print("OS Detection: Linux/Unix")
            elif response.getlayer(TCP).flags == 0x10:
                print("OS Detection: Windows")
            else:
                print("OS Detection: Unknown")
        else:
            print("OS Detection: Unknown")
    else:
        print("OS Detection: No response")

def main():
    parser = argparse.ArgumentParser(description="Simple NMAP-like scanner with OS detection")
    parser.add_argument("host", help="Host to scan")
    parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)", default="22,80,443")
    args = parser.parse_args()

    host = args.host
    ports = [int(p) for p in args.ports.split(",")]

    print(f"Scanning {host}...")
    scan_host(host, ports)
    os_detection(host)

if __name__ == "__main__":
    main()