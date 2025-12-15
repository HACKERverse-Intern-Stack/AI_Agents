# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1105 - Ingress Tool Transfer
# Objective: Simulate the transfer of tools or files from a remote system to a compromised host.

# t1105_ingress_tool_transfer.py
import requests
import os

# --- Simulation Configuration ---
# A known, safe text file for demonstration. DO NOT download real malware.
FILE_URL = "https://www.learningcontainer.com/wp-content/uploads/2020/05/sample-txt-file.txt"
OUTPUT_PATH = "downloaded_payload.txt" # A suspicious name for the downloaded file

def simulate_ingress_tool_transfer(url, path):
    """
    Simulates T1105 by downloading a file from a remote location.
    This is a benign action (downloading a text file) but the context is what makes it malicious.
    Defenders should watch for suspicious processes downloading files from the internet.
    """
    print(f"[*] T1105 Simulation: Transferring tool from '{url}' to '{path}'")
    try:
        response = requests.get(url, stream=True, timeout=15)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        with open(path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"[+] Successfully downloaded file to {path}. Size: {os.path.getsize(path)} bytes.")
        print("[!] In a real attack, this would be a malicious binary or script.")
        print("[*] Cleaning up downloaded file...")
        os.remove(path)

    except requests.exceptions.RequestException as e:
        print(f"[!] Failed to download file: {e}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    simulate_ingress_tool_transfer(FILE_URL, OUTPUT_PATH)