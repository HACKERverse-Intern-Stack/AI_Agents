# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1046 - Network Service Scanning
# Objective: Adversaries may attempt to identify running services and open ports on a target host. This script simulates a port scan against a target to discover what services are listening. The network traffic generated is identical to a real attacker's reconnaissance scan.

# t1046_network_service_scanning.py
import socket
import sys
import threading
import time

# --- Simulation Configuration ---
TARGET_HOST = input("Enter the specific IP address of target host: ") # Grab user input of target ip address
# Common ports to scan
PORTS_TO_SCAN = [20,21,22,23,25,53,67,68,69,80,88,110,111,119,123,135,137,138,139,143,161,162,179,194,389,443,445,464,465,500,514,515,520,587,636,646,989,990,993,995,1194,1701,1723,1935,2049,2375,2376,27015,3074,3268,3269,3389,3784,3785,4500,5222,5900,6443,6667,8080,9000]
TIMEOUT = 1 # Timeout for each connection attempt in seconds

def scan_port(host, port, open_ports):
    """
    Attempts to connect to a specific port on a host.
    If successful, it adds the port to the list of open ports.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Attempts TCP connection
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