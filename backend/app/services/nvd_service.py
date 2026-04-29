from datetime import datetime, timedelta, timezone
import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def get_nvd_cve(cve_id: str):
    try:
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            timeout=30,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        return {
            "found": False,
            "source": "nvd",
            "error": "NVD request timed out. Try refreshing again."
        }

    except requests.exceptions.ConnectionError:
        return {
            "found": False,
            "source": "nvd",
            "error": "Could not connect to NVD. Check internet/Docker network and try again."
        }

    except requests.exceptions.HTTPError as error:
        return {
            "found": False,
            "source": "nvd",
            "error": f"NVD returned HTTP error: {error}"
        }

    except requests.exceptions.RequestException as error:
        return {
            "found": False,
            "source": "nvd",
            "error": f"NVD request failed: {error}"
        }

    data = response.json()

    if not data.get("vulnerabilities"):
        return {
            "found": False,
            "source": "nvd",
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
        "source": "nvd",
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss": cvss_data,
        "weaknesses": cve.get("weaknesses", []),
        "references": cve.get("references", []),
    }

def extract_cve_summary(cve: dict):
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
        "source": "nvd",
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss": cvss_data,
        "weaknesses": cve.get("weaknesses", []),
        "references": cve.get("references", []),
    }


def get_latest_nvd_cves(days: int = 7, limit: int = 20):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)

    base_params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
    }

    try:
        # First call: get total result count for the date window
        count_response = requests.get(
            NVD_URL,
            params={
                **base_params,
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            timeout=30,
        )
        count_response.raise_for_status()
        count_data = count_response.json()

        total_results = count_data.get("totalResults", 0)

        if total_results == 0:
            return {
                "found": True,
                "source": "nvd",
                "total_results": 0,
                "results_per_page": limit,
                "items": [],
            }

        # NVD API tends to return earlier entries first in the selected window.
        # So fetch near the end of the result set to get the latest CVEs.
        start_index = max(total_results - limit, 0)

        response = requests.get(
            NVD_URL,
            params={
                **base_params,
                "resultsPerPage": limit,
                "startIndex": start_index,
            },
            timeout=30,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        return {
            "found": False,
            "source": "nvd",
            "error": "NVD request timed out. Try refreshing again.",
            "items": [],
        }

    except requests.exceptions.ConnectionError:
        return {
            "found": False,
            "source": "nvd",
            "error": "Could not connect to NVD. Check internet/Docker network and try again.",
            "items": [],
        }

    except requests.exceptions.RequestException as error:
        return {
            "found": False,
            "source": "nvd",
            "error": f"NVD request failed: {error}",
            "items": [],
        }

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    items = [
        extract_cve_summary(item["cve"])
        for item in vulnerabilities
        if "cve" in item
    ]

    # Force newest first for frontend display
    items.sort(
        key=lambda item: item.get("published") or "",
        reverse=True,
    )

    return {
        "found": True,
        "source": "nvd",
        "total_results": total_results,
        "results_per_page": limit,
        "start_index": start_index,
        "items": items,
    }

def search_nvd_cves(
    results_per_page: int = 25,
    page: int = 1,
    keyword: str | None = None,
):
    page = max(page, 1)
    results_per_page = min(max(results_per_page, 1), 100)

    params = {
        "resultsPerPage": results_per_page,
    }

    if keyword:
        params["keywordSearch"] = keyword

    try:
        # First call: get total count from entire NVD database
        count_response = requests.get(
            NVD_URL,
            params={**params, "resultsPerPage": 1, "startIndex": 0},
            timeout=30,
        )
        count_response.raise_for_status()
        count_data = count_response.json()

        total_results = count_data.get("totalResults", 0)

        if total_results == 0:
            return {
                "found": True,
                "source": "nvd",
                "page": page,
                "results_per_page": results_per_page,
                "total_results": 0,
                "total_pages": 0,
                "items": [],
            }

        total_pages = (total_results + results_per_page - 1) // results_per_page

        # NVD API ordering is older-first.
        # To make page 1 show latest CVEs, we invert the startIndex.
        start_index = max(total_results - (page * results_per_page), 0)

        actual_page_size = results_per_page
        if start_index == 0:
            actual_page_size = total_results - ((total_pages - 1) * results_per_page)
            actual_page_size = max(actual_page_size, 1)

        response = requests.get(
            NVD_URL,
            params={
                **params,
                "resultsPerPage": actual_page_size,
                "startIndex": start_index,
            },
            timeout=30,
        )
        response.raise_for_status()

    except requests.exceptions.Timeout:
        return {
            "found": False,
            "source": "nvd",
            "error": "NVD request timed out. Try refreshing again.",
            "items": [],
        }

    except requests.exceptions.ConnectionError:
        return {
            "found": False,
            "source": "nvd",
            "error": "Could not connect to NVD. Check internet/Docker network and try again.",
            "items": [],
        }

    except requests.exceptions.RequestException as error:
        return {
            "found": False,
            "source": "nvd",
            "error": f"NVD request failed: {error}",
            "items": [],
        }

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    items = [
        extract_cve_summary(item["cve"])
        for item in vulnerabilities
        if "cve" in item
    ]

    items.sort(
        key=lambda item: item.get("published") or "",
        reverse=True,
    )

    return {
        "found": True,
        "source": "nvd",
        "page": page,
        "results_per_page": results_per_page,
        "total_results": total_results,
        "total_pages": total_pages,
        "start_index": start_index,
        "items": items,
    }