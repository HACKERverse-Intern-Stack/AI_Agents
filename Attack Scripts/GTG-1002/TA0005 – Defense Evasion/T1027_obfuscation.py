# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1027 - Obfuscation
# Objective: Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents. This script simulates a simple XOR obfuscation of a string.

# t1027_obfuscation.py
import os

# --- Simulation Configuration ---
# The "malicious" command we want to hide
MALICIOUS_COMMAND = "whoami /all"
# A simple single-byte key for XOR obfuscation
XOR_KEY = 0xAA
OBFUSCATED_FILE = "obfuscated_payload.bin"

def simulate_obfuscation(data, key, output_path):
    """
    Simulates T1027 by obfuscating a string using a simple XOR cipher
    and saving it to a binary file.
    """
    print(f"[*] T1027 Simulation: Obfuscating information.")
    print(f"[*] Original data: '{data}'")
    print(f"[*] Using XOR key: 0x{key:02x}")
    
    # 1. Obfuscate the data
    obfuscated_bytes = bytes([b ^ key for b in data.encode('utf-8')])
    print(f"[*] Obfuscated bytes (hex): {obfuscated_bytes.hex()}")
    
    # 2. Save the obfuscated data to a file
    try:
        with open(output_path, 'wb') as f:
            f.write(obfuscated_bytes)
        print(f"[+] Saved obfuscated data to '{output_path}'")
        
        # 3. Simulate de-obfuscation (what the malware would do at runtime)
        print("[*] Simulating runtime de-obfuscation...")
        deobfuscated_bytes = bytes([b ^ key for b in obfuscated_bytes])
        deobfuscated_command = deobfuscated_bytes.decode('utf-8')
        print(f"[+] De-obfuscated command: '{deobfuscated_command}'")
        
        # 4. Clean up
        print("[*] Cleaning up obfuscated file...")
        os.remove(output_path)
        
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    simulate_obfuscation(MALICIOUS_COMMAND, XOR_KEY, OBFUSCATED_FILE)