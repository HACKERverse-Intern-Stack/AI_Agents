import argparse
import json
import time

def harvest_creds(source):
    print(f"[*] Searching for credentials in {source}...")
    time.sleep(1)
    
    # Simulated harvested credentials
    creds = [
        {"type": "AWS_ACCESS_KEY", "value": "AKIAIOSFODNN7EXAMPLE", "source": ".env"},
        {"type": "DB_PASSWORD", "value": "P@ssw0rd123!", "source": "config.php"},
        {"type": "SSH_KEY", "value": "-----BEGIN RSA PRIVATE KEY-----...", "source": "id_rsa"}
    ]
    
    print(f"[+] Found {len(creds)} valid credentials.")
    with open("harvested_creds.json", "w") as f:
        json.dump(creds, f, indent=4)
    print("[*] Credentials saved to harvested_creds.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    harvest_creds(args.source)