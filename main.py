import json
import os
from datetime import datetime
from core.cve_mapping import find_tech_stack , normalize_tech_stack, search_cves_nvd, response_header_analyse


def cve_mapping(url):
    
    tech_stack = find_tech_stack(url)
    server_stack = response_header_analyse(url)
    
    techs = normalize_tech_stack(tech_stack , server_stack)
    report = {
        "url": url,
        "detected_technologies": techs,
        "cve_mapping": {}
    }

    for tech in techs:
        cves = search_cves_nvd(tech)
        report["cve_mapping"][tech] = cves if cves else ["No known CVEs found."]
        
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = os.path.join("data", f"cve_report_{timestamp}.json")

    with open(output_file, "w") as f:
        json.dump(report, f, indent=4)

    print(f"CVE report saved to: {output_file}")

if __name__ == "__main__":
    url = "https://demo.testfire.net"
    cve_mapping(url)
            

    