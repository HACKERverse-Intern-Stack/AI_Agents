# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1204 - User Execution
# Objective: Adversaries may rely on a user executing a malicious file. This script simulates creating a malicious-looking LNK (shortcut) file that would execute a command when clicked by a user.

# t1204_user_execution.py
import os
import struct

# --- Simulation Configuration ---
# This LNK file, when double-clicked, will launch cmd.exe and echo a message.
# It's harmless but demonstrates the technique.
ATTACK_LNK_PATH = "Important_Document.lnk"
TARGET_EXECUTABLE = "C:\\Windows\\System32\\cmd.exe"
ARGUMENTS = "/c echo You have been pwned by T1204! & pause"

def create_malicious_lnk(lnk_path, target_path, arguments):
    """
    Simulates T1204 by creating a malicious LNK file.
    This requires a complex binary structure, so this is a simplified example.
    A real LNK has more fields for icons, etc.
    """
    print(f"[*] T1204 Simulation: Creating malicious LNK file at '{lnk_path}'")
    print(f"    - Target: {target_path}")
    print(f"    - Arguments: {arguments}")
    
    try:
        # This is a highly simplified LNK structure. Real LNK files are more complex.
        # We are creating the minimum viable structure for a working shortcut on Windows.
        with open(lnk_path, 'wb') as f:
            # LNK Header
            f.write(b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46')
            
            # LinkTargetIDList (empty)
            f.write(struct.pack('<H', 0x0000))
            
            # LinkInfo (empty for simplicity)
            f.write(struct.pack('<I', 0x00000000))
            
            # StringData
            # The path to the target executable
            target_path_bytes = target_path.encode('utf-16le')
            f.write(struct.pack('<H', len(target_path_bytes)))
            f.write(target_path_bytes)

            # Arguments string
            arguments_bytes = arguments.encode('utf-16le')
            f.write(struct.pack('<H', len(arguments_bytes)))
            f.write(arguments_bytes)

        print(f"[+] Successfully created malicious LNK file at '{lnk_path}'.")
        print("[!] In a real attack, a user would be tricked into double-clicking this.")
        print("[*] Cleaning up created file...")
        os.remove(lnk_path)

    except Exception as e:
        print(f"[!] An error occurred creating the LNK file: {e}")

if __name__ == "__main__":
    # This script is best run on a Windows host to create a valid .lnk file.
    if os.name == 'nt':
        create_malicious_lnk(ATTACK_LNK_PATH, TARGET_EXECUTABLE, ARGUMENTS)
    else:
        print("[-] This simulation is designed to run on Windows to create a valid .lnk file.")