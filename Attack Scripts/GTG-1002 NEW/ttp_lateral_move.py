import argparse
import json
import time

def lateral_move(creds_file):
    print("[*] Loading credentials for lateral movement...")
    try:
        with open(creds_file, 'r') as f:
            creds = json.load(f)
    except FileNotFoundError:
        print("[-] Credential file not found.")
        exit(1)

    print(f"[*] Testing {len(creds)} credentials against internal subnet 10.0.0.0/24...")
    time.sleep(2)
    
    print("[+] Successful authentication to Internal_DB (10.0.0.15)")
    print("[+] Successful authentication to Backup_Server (10.0.0.20)")
    
    # Create a marker for the next stage
    with open("lateral_movement_success.txt", "w") as f:
        f.write("10.0.0.15\n10.0.0.20")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--creds", required=True)
    args = parser.parse_args()
    lateral_move(args.creds)