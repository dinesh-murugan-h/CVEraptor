import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_nvd_cve(cve_id: str):
    response = requests.get(
        NVD_URL,
        params={"cveId": cve_id},
        timeout=20,
    )
    response.raise_for_status()

    data = response.json()

    if not data.get("vulnerabilities"):
        return {
            "found": False,
            "message": "CVE not found in NVD"
        }

    cve = data["vulnerabilities"][0]["cve"]
    metrics = cve.get("metrics", {})

    selected_metric = None
    cvss_version = None

    if "cvssMetricV40" in metrics:
        selected_metric = metrics["cvssMetricV40"][0]
        cvss_version = "4.0"
    elif "cvssMetricV31" in metrics:
        selected_metric = metrics["cvssMetricV31"][0]
        cvss_version = "3.1"
    elif "cvssMetricV30" in metrics:
        selected_metric = metrics["cvssMetricV30"][0]
        cvss_version = "3.0"
    elif "cvssMetricV2" in metrics:
        selected_metric = metrics["cvssMetricV2"][0]
        cvss_version = "2.0"

    cvss_data = {
        "available": False
    }

    if selected_metric:
        cvss = selected_metric.get("cvssData", {})

        cvss_data = {
            "available": True,
            "version": cvss_version,
            "source": selected_metric.get("source"),
            "type": selected_metric.get("type"),
            "base_score": cvss.get("baseScore"),
            "base_severity": cvss.get("baseSeverity") or selected_metric.get("baseSeverity"),
            "vector": cvss.get("vectorString"),
            "exploitability_score": selected_metric.get("exploitabilityScore"),
            "impact_score": selected_metric.get("impactScore"),
        }

    description = next(
        (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        None,
    )

    return {
        "found": True,
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss": cvss_data,
        "weaknesses": cve.get("weaknesses", []),
        "references": cve.get("references", []),
    }