# t1590_gather_host_info.py
import socket

# --- Simulation Configuration ---
TARGET_DOMAIN = "www.google.com"  # A safe, public domain for simulation

def simulate_gather_host_info(domain):
    """
    Simulates T1590 by performing a DNS lookup to resolve a domain name.
    This is a standard network request, but in an attack context, it's reconnaissance.
    """
    print(f"[*] T1590 Simulation: Gathering host information for {domain}")
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"[+] Resolved {domain} to IP address: {ip_address}")
    except socket.gaierror:
        print(f"[-] Could not resolve hostname: {domain}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    simulate_gather_host_info(TARGET_DOMAIN)