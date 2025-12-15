# t1595_active_scanning.py
import socket
import sys
import time

# --- Simulation Configuration ---
TARGET_HOST = "127.0.0.1"  # Use localhost for safe simulation
TARGET_PORT = 445  # Commonly targeted SMB port
TIMEOUT = 2

def simulate_vulnerability_scan(host, port):
    """
    Simulates T1595 by attempting to grab a service banner from a known port.
    This is a benign action that mimics the reconnaissance step of an attacker.
    """
    print(f"[*] T1595 Simulation: Active Scanning for vulnerabilities on {host}:{port}")
    try:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        
        # Attempt to connect to the target port
        result = s.connect_ex((host, port))
        
        if result == 0:
            print(f"[+] Port {port} is OPEN. Attempting to grab service banner...")
            # Send a simple probe to elicit a response (e.g., for HTTP, FTP, etc.)
            # For SMB, a simple connection is often enough to get a banner from the OS.
            s.send(b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x06\x00\x00\x01\x00\x00\x81\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4d\x49\x43\x52\x4f\x53\x4f\x46\x54\x20\x4e\x45\x54\x57\x4f\x52\x4b\x53\x20\x31\x2e\x30\x33\x00")
            banner = s.recv(1024)
            if banner:
                print(f"[!] Service Banner Received: {banner.strip()}")
            else:
                print("[!] No banner received on open port.")
        else:
            print(f"[-] Port {port} is closed.")

    except socket.timeout:
        print(f"[-] Connection to {host}:{port} timed out.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
    finally:
        s.close()

if __name__ == "__main__":
    simulate_vulnerability_scan(TARGET_HOST, TARGET_PORT)