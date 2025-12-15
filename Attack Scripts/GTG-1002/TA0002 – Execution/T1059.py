# t1059_command_interpreter.py
import subprocess
import platform

def simulate_cmd_execution():
    """Simulates T1059.001 (Command Prompt) execution."""
    command = "echo T1059.001: Executing via cmd.exe"
    print(f"[*] T1059.001 Simulation: Executing command: '{command}'")
    try:
        # Using os.system to directly invoke the system's shell
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed with exit code {e.returncode}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

def simulate_powershell_execution():
    """Simulates T1059.001 (PowerShell) execution."""
    # A common obfuscation technique is to encode commands
    command = "Write-Host 'T1059.001: Executing via PowerShell'"
    print(f"[*] T1059.001 Simulation: Executing PowerShell command: '{command}'")
    try:
        if platform.system() == "Windows":
            # Direct execution
            subprocess.run(["powershell.exe", "-Command", command], check=True)
            
            # Encoded execution (more evasive)
            encoded_command = subprocess.run(["powershell.exe", "-Command", f"[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('{command}'))"], capture_output=True, text=True).stdout.strip()
            print(f"[*] Executing encoded command: {encoded_command}")
            subprocess.run(["powershell.exe", "-EncodedCommand", encoded_command], check=True)
        else:
            print("[-] PowerShell is not available on this platform.")
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[!] PowerShell command failed: {e}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    simulate_cmd_execution()
    simulate_powershell_execution()