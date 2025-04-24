import warnings
warnings.filterwarnings("ignore", category=UserWarning)

from Wappalyzer import Wappalyzer, WebPage
import requests



def find_tech_stack(url):
    try: 
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        # tech_stack = wappalyzer.analyze(webpage)
        tech_stack = wappalyzer.analyze_with_versions_and_categories(webpage)
        return tech_stack
    except Exception as e:
        return {"error": str(e)}, False

def response_header_analyse(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        info = {}

        if 'Server' in headers:
            info['Web Server'] = headers['Server']

        if 'X-Powered-By' in headers:
            info['Powered By'] = headers['X-Powered-By']

        if 'Via' in headers:
            info['Proxy/CDN'] = headers['Via']

        return info

    except requests.RequestException as e:
        return {"error": str(e)}, False

def normalize_tech_stack(raw_stack, server_stack):
    tech_list = []
    for tech, details in raw_stack.items():
        versions = details.get("versions", [])
        if versions:
            for version in versions:
                tech_list.append(f"{tech} {version}")
    if server_stack:
        for tech, details in server_stack.items():
            details = details.replace("/"," ")
            details = details.replace("-"," ")  
            tech_list.append(details)
    return tech_list

def search_cves_nvd(tech_version):
    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": tech_version,
            "resultsPerPage": 5 
        }
        response = requests.get(base_url, params=params, timeout=15)
        if response.status_code == 200:
            data = response.json()
            cves = [item["cve"]["id"] for item in data.get("vulnerabilities", [])]
            return cves
        else:
            return [f"Error: HTTP {response.status_code}"]
    except Exception as e:
        return [f"Error: {e}"]
