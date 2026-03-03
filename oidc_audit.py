import csv
import requests
import time
import getpass
from urllib.parse import urlencode
from datetime import datetime, timedelta, timezone

# --- Configuration ---
INPUT_CSV = "app_ids.csv"     
OUTPUT_CSV = "oidc_security_audit.csv"
MAX_LOG_PAGES = 50 

def make_request(url, headers):
    """Makes a GET request to the Okta API, handling pagination and 429 Rate Limits."""
    results = []
    
    while url:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 429:
            reset_time = int(response.headers.get("X-Rate-Limit-Reset", time.time() + 10))
            sleep_duration = max(1, reset_time - int(time.time()) + 1)
            print(f"    [!] Rate limit hit. Sleeping for {sleep_duration} seconds...")
            time.sleep(sleep_duration)
            continue 
            
        if response.status_code != 200:
            return None, response.status_code

        data = response.json()
        if isinstance(data, list):
            results.extend(data)
        else:
            return data, 200 

        url = None
        if "link" in response.headers:
            links = response.headers["link"].split(",")
            for link in links:
                if 'rel="next"' in link:
                    url = link[link.index("<")+1 : link.index(">")]
                    break

        if not isinstance(data, list):
            break

    return results, 200

def audit_oidc_app(app_id, base_url, headers):
    print(f"Processing App ID: {app_id}")
    metrics = {
        "app_id": app_id,
        "app_name": "N/A",
        "status": "NOT_FOUND",
        "sign_on_mode": "UNKNOWN",
        "auth_policy_name": "N/A",
        "application_urls": "N/A",
        "assigned_users": 0,
        "total_logins_90d": 0,
        "unique_users_90d": 0,
        "last_login_date": "No logins in 90 days",
        "implicit_grant_enabled": False,
        "requests_access_token": False,
        "requests_id_token": False,
        "has_wildcard_uri": False
    }

    # 1. Get App Details
    app_info, status_code = make_request(f"{base_url}/api/v1/apps/{app_id}", headers)
    if status_code != 200 or not app_info:
        print(f"    - App {app_id} not found or error ({status_code}).")
        return metrics
    
    metrics["app_name"] = app_info.get("label", "Unknown")
    metrics["status"] = app_info.get("status", "UNKNOWN")
    metrics["sign_on_mode"] = app_info.get("signOnMode", "UNKNOWN")

    # Only process OIDC specific settings if it's an OIDC app
    if metrics["sign_on_mode"] == "OPENID_CONNECT":
        oauth_settings = app_info.get("settings", {}).get("oauthClient", {})
        redirect_uris = oauth_settings.get("redirect_uris", [])
        initiate_uri = oauth_settings.get("initiate_login_uri", "")
        
        # Build URLs string
        all_urls = redirect_uris.copy()
        if initiate_uri:
            all_urls.append(f"Initiation: {initiate_uri}")
        metrics["application_urls"] = " | ".join(all_urls) if all_urls else "None"
        
        # Security Flags
        metrics["implicit_grant_enabled"] = "implicit" in oauth_settings.get("grant_types", [])
        metrics["requests_access_token"] = "token" in oauth_settings.get("response_types", [])
        metrics["requests_id_token"] = "id_token" in oauth_settings.get("response_types", [])
        metrics["has_wildcard_uri"] = any("*" in uri for uri in redirect_uris)
        
        # 2. Get Authentication Policy Name
        policy_link = app_info.get("_links", {}).get("accessPolicy", {}).get("href")
        if policy_link:
            policy_data, p_status = make_request(policy_link, headers)
            if p_status == 200 and policy_data:
                metrics["auth_policy_name"] = policy_data.get("name", "Unknown Policy")

    # 3. Get Assigned User Count
    if metrics["status"] != "INACTIVE":
        users, _ = make_request(f"{base_url}/api/v1/apps/{app_id}/users", headers)
        metrics["assigned_users"] = len(users) if users else 0

    # 4. Get Usage Logs 
    if metrics["status"] == "ACTIVE":
        client_id = app_info.get("credentials", {}).get("oauthClient", {}).get("client_id")
        search_id = client_id if client_id else app_id
        
        query = f'(target.id eq "{search_id}" or client.id eq "{search_id}") and outcome.result eq "SUCCESS"'
        since_date = (datetime.now(timezone.utc) - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        params = {"filter": query, "since": since_date, "sortOrder": "DESCENDING", "limit": 100}
        log_url = f"{base_url}/api/v1/logs?{urlencode(params)}"
        
        unique_users = set()
        total_logins = 0
        pages_fetched = 0
        
        url_to_fetch = log_url
        while url_to_fetch and pages_fetched < MAX_LOG_PAGES:
            response = requests.get(url_to_fetch, headers=headers)
            
            if response.status_code == 429:
                time.sleep(5)
                continue
                
            if response.status_code != 200:
                print(f"    [!] Error fetching logs for {app_id}. HTTP Status: {response.status_code}")
                break
                
            logs = response.json()
            if not logs:
                break
                
            if pages_fetched == 0 and len(logs) > 0:
                metrics["last_login_date"] = logs[0].get("published")
                
            for log in logs:
                event_type = log.get("eventType", "")
                if "user.authentication.sso" in event_type or "oauth2" in event_type:
                    actor_id = log.get("actor", {}).get("alternateId", "Unknown Entity")
                    total_logins += 1
                    unique_users.add(actor_id)
            
            url_to_fetch = None
            if "link" in response.headers:
                for link in response.headers["link"].split(","):
                    if 'rel="next"' in link:
                        url_to_fetch = link[link.index("<")+1 : link.index(">")]
                        break
            
            pages_fetched += 1
            
        metrics["total_logins_90d"] = total_logins
        metrics["unique_users_90d"] = len(unique_users)

    return metrics

def main():
    print("--- Okta OIDC Security & Usage Audit ---")
    
    okta_domain = input("Enter your Okta Domain (e.g., yourdomain.okta.com): ").strip()
    okta_api_token = getpass.getpass("Enter your Okta API Token (typing will be hidden): ").strip()

    if not okta_domain or not okta_api_token:
        print("Error: Both Domain and API Token are required to run this script.")
        return

    okta_domain = okta_domain.replace("https://", "").rstrip("/")
    base_url = f"https://{okta_domain}"
    
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"SSWS {okta_api_token}"
    }

    app_ids = []
    try:
        with open(INPUT_CSV, mode='r', encoding='utf-8') as infile:
            reader = csv.DictReader(infile)
            for row in reader:
                if 'app_id' in row:
                    app_ids.append(row['app_id'].strip())
    except FileNotFoundError:
        print(f"\nError: Could not find '{INPUT_CSV}'. Please create it in the same folder and add an 'app_id' column header.")
        return

    if not app_ids:
        print("\nNo App IDs found. Check your CSV format.")
        return

    print(f"\nFound {len(app_ids)} App IDs to process. Starting audit...\n")

    # Define the exact order of columns for the CSV
    fieldnames = [
        "app_id", "app_name", "status", "sign_on_mode", "auth_policy_name", 
        "application_urls", "implicit_grant_enabled", "requests_access_token", 
        "requests_id_token", "has_wildcard_uri", "assigned_users", 
        "total_logins_90d", "unique_users_90d", "last_login_date"
    ]
    
    with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for app_id in app_ids:
            if not app_id: 
                continue 
            
            metrics = audit_oidc_app(app_id, base_url, headers)
            writer.writerow(metrics)
            
    print(f"\n✅ Done! Consolidated security metrics have been written to {OUTPUT_CSV}")

if __name__ == "__main__":
    main()