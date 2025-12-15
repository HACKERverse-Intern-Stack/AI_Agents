# < ---- DOCUMENTATION OF MITRE ATT&CK TECHNIQUE ---- >
# T1593 - Search Open Websites
# Objective: Adversaries may search through open websites or domains for information about victims. This script simulates using a web search API (or just making an HTTP request) to find information.
# t1593_search_open_websites.py
import requests
import urllib.parse

# --- Simulation Configuration ---
SEARCH_ENGINE = "https://duckduckgo.com/html/"
SEARCH_QUERY = "site:github.com \"password.txt\"" # A common dorking technique

def simulate_search_open_websites(query):
    """
    Simulates T1593 by making a web search request.
    This is how an attacker might find leaked documents or vulnerable infrastructure.
    NOTE: This script makes a real network request to a search engine.
    """
    print(f"[*] T1593 Simulation: Searching open websites for: '{query}'")
    
    # URL-encode the query
    encoded_query = urllib.parse.quote_plus(query)
    full_url = f"{SEARCH_ENGINE}?q={encoded_query}"
    
    try:
        # Use a common user agent to avoid being blocked
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(full_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            print(f"[+] Successfully queried search engine. Response length: {len(response.text)} bytes.")
            print("[!] In a real attack, the adversary would parse this HTML for links to sensitive files.")
            # For safety, we won't print the actual search results.
        else:
            print(f"[-] Search request failed with status code: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[!] An error occurred during the web request: {e}")

if __name__ == "__main__":
    simulate_search_open_websites(SEARCH_QUERY)