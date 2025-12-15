# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1036 - Masquerading
# Objective: Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and security tools. This script simulates renaming a malicious executable to look like a trusted system process.

# t1036_masquerading.py
import os
import shutil
import sys

# --- Simulation Configuration ---
# Create a fake malicious payload
FAKE_MALWARE_NAME = "malicious_payload.exe"
# Masquerade as a legitimate Windows system file
MASQUERADED_NAME = "svchost.exe"

def simulate_masquerading(fake_malware_path, masqueraded_path):
    """
    Simulates T1036 by creating a dummy file and renaming it to masquerade
    as a legitimate system process.
    """
    print(f"[*] T1036 Simulation: Masquerading a malicious artifact.")
    
    try:
        # 1. Create a fake malicious file
        print(f"[*] Creating fake malicious payload: '{fake_malware_path}'")
        with open(fake_malware_path, "w") as f:
            f.write("This is not real malware, just a placeholder for simulation.")
        
        # 2. Masquerade the file by renaming it
        print(f"[*] Masquerading '{fake_malware_path}' as '{masqueraded_path}'")
        # In a real attack, this would likely be done in a suspicious directory
        # like C:\Users\Public\ or C:\Temp\ to avoid overwriting the real file.
        # We'll do it in the current directory for safety.
        shutil.move(fake_malware_path, masqueraded_path)
        
        print(f"[+] Successfully masqueraded file. Current directory now contains '{masqueraded_path}'.")
        print("[!] A defender should be suspicious of 'svchost.exe' running from a non-system path.")
        
        # 3. Clean up the masqueraded file
        print("[*] Cleaning up masqueraded file...")
        os.remove(masqueraded_path)
        print("[+] Cleanup complete.")

    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    # Use a temporary directory to avoid polluting the current one
    temp_dir = "temp_simulation_dir"
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
    
    simulate_masquerading(
        os.path.join(temp_dir, FAKE_MALWARE_NAME),
        os.path.join(temp_dir, MASQUERADED_NAME)
    )
    
    # Remove the temporary directory
    os.rmdir(temp_dir)