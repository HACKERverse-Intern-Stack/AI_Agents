# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1078.004 - Valid Accounts: Cloud Accounts
# Objective: Adversaries may obtain and abuse credentials of cloud accounts. This script simulates using a (fake) cloud API key to interact with a cloud service provider.

# t1078_004_cloud_accounts.py
import os
import requests
import json

# --- Simulation Configuration ---
# These are fake credentials. In a real attack, these would be stolen.
FAKE_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
FAKE_AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
FAKE_AWS_REGION = "us-east-1"
# A real AWS API endpoint for listing S3 buckets
API_ENDPOINT = f"https://s3.{FAKE_AWS_REGION}.amazonaws.com/"

def simulate_cloud_account_use(access_key, secret_key):
    """
    Simulates T1078.004 by attempting to make an authenticated API call to a cloud provider.
    This will fail with invalid credentials, but the attempt is the key artifact.
    """
    print(f"[*] T1078.004 Simulation: Attempting to use a valid cloud account.")
    print(f"    - Using Access Key: {access_key[:8]}...")
    print(f"    - Targeting AWS S3 API in {FAKE_AWS_REGION}")
    
    # AWS Signature Version 4 is complex. We will simulate the *attempt* by sending
    # a request with the key in the header, which will fail but is observable.
    headers = {
        'Authorization': f'AWS4-HMAC-SHA256 Credential={access_key}/{20231015}/{FAKE_AWS_REGION}/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=fakesig',
        'x-amz-date': '20231015T120000Z',
        'Host': f"s3.{FAKE_AWS_REGION}.amazonaws.com"
    }
    
    try:
        response = requests.get(API_ENDPOINT, headers=headers, timeout=10)
        
        print(f"[+] API call executed. Status Code: {response.status_code}")
        print(f"[!] Response Body: {response.text[:200]}...") # Print part of the error message
        
        if response.status_code == 403:
            print("[!] Received 403 Forbidden, as expected with fake credentials. The attempt is logged by AWS.")
        else:
            print(f"[!] Received an unexpected status code.")

    except requests.exceptions.RequestException as e:
        print(f"[!] An error occurred during the API request: {e}")

if __name__ == "__main__":
    simulate_cloud_account_use(FAKE_AWS_ACCESS_KEY, FAKE_AWS_SECRET_KEY)