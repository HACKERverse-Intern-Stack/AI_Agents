# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1046 - Network Service Scanning
# Objective: Adversaries may attempt to identify running services and open ports on a target host. This script simulates a port scan against a target to discover what services are listening. The network traffic generated is identical to a real attacker's reconnaissance scan.

# t1046_network_service_scanning.py
import socket
import sys
import threading
import time

# --- Simulation Configuration ---
TARGET_HOST = "127.0.0.1"  # Use localhost for safe simulation
# Common ports to scan
PORTS_TO_SCAN = [21, 22, 23, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3389]
TIMEOUT = 1 # Timeout for each connection attempt in seconds

def scan_port(host, port, open_ports):
    """
    Attempts to connect to a specific port on a host.
    If successful, it adds the port to the list of open ports.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        result = s.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
        s.close()
    except Exception as e:
        # Silently handle exceptions for cleaner output during multi-threaded scanning
        pass

def simulate_network_service_scanning(host, ports):
    """
    Simulates T1046 by performing a multi-threaded TCP port scan.
    This generates network traffic that is identical to a real attacker's reconnaissance scan.
    """
    print(f"[*] T1046 Simulation: Starting network service scan on {host}")
    print(f"[*] Scanning {len(ports)} common ports...")
    
    open_ports = []
    threads = []
    
    start_time = time.time()
    
    # Create and start a thread for each port
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(host, port, open_ports))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    end_time = time.time()
    
    print("\n--- Scan Results ---")
    if open_ports:
        print(f"[+] Found {len(open_ports)} open ports: {sorted(open_ports)}")
    else:
        print("[-] No open ports found on the target list.")
    print(f"[*] Scan completed in {end_time - start_time:.2f} seconds.")

if __name__ == "__main__":
    simulate_network_service_scanning(TARGET_HOST, PORTS_TO_SCAN)