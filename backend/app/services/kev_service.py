import requests


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get_kev_status(cve_id: str):
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    for item in vulnerabilities:
        if item.get("cveID") == cve_id:
            return {
                "found": True,
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "date_added": item.get("dateAdded"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "due_date": item.get("dueDate"),
                "notes": item.get("notes"),
            }

    return {
        "found": False,
        "message": "CVE not found in CISA KEV catalog"
    }