import time
import requests


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache = {
    "loaded_at": 0,
    "data": {},
}

CACHE_TTL_SECONDS = 3600


def load_kev_catalog():
    now = time.time()

    if _kev_cache["data"] and now - _kev_cache["loaded_at"] < CACHE_TTL_SECONDS:
        return _kev_cache["data"]

    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    kev_map = {}

    for item in vulnerabilities:
        cve_id = item.get("cveID")
        if not cve_id:
            continue

        kev_map[cve_id] = {
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

    _kev_cache["loaded_at"] = now
    _kev_cache["data"] = kev_map

    return kev_map


def get_kev_status(cve_id: str):
    try:
        kev_map = load_kev_catalog()
    except requests.exceptions.RequestException:
        return {
            "found": False,
            "error": "Could not load CISA KEV catalog"
        }

    return kev_map.get(
        cve_id,
        {
            "found": False,
            "message": "CVE not found in CISA KEV catalog"
        }
    )


def get_kev_batch(cve_ids: list[str]):
    try:
        kev_map = load_kev_catalog()
    except requests.exceptions.RequestException:
        return {
            cve_id: {
                "found": False,
                "error": "Could not load CISA KEV catalog"
            }
            for cve_id in cve_ids
        }

    return {
        cve_id: kev_map.get(
            cve_id,
            {
                "found": False,
                "message": "CVE not found in CISA KEV catalog"
            }
        )
        for cve_id in cve_ids
    }