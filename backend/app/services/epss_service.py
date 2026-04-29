import requests


EPSS_URL = "https://api.first.org/data/v1/epss"


def get_epss(cve_id: str):
    response = requests.get(
        EPSS_URL,
        params={"cve": cve_id},
        timeout=20,
    )
    response.raise_for_status()

    data = response.json()
    rows = data.get("data", [])

    if not rows:
        return {
            "found": False,
            "message": "No EPSS data found"
        }

    row = rows[0]

    return {
        "found": True,
        "epss": float(row["epss"]),
        "percentile": float(row["percentile"]),
        "date": row.get("date"),
    }

def get_epss_batch(cve_ids: list[str]):
    if not cve_ids:
        return {}

    joined_cves = ",".join(cve_ids)

    try:
        response = requests.get(
            EPSS_URL,
            params={"cve": joined_cves},
            timeout=30,
        )
        response.raise_for_status()

    except requests.exceptions.RequestException:
        return {}

    data = response.json()
    rows = data.get("data", [])

    results = {}

    for row in rows:
        cve = row.get("cve")
        if not cve:
            continue

        results[cve] = {
            "found": True,
            "epss": float(row["epss"]) if row.get("epss") is not None else None,
            "percentile": float(row["percentile"]) if row.get("percentile") is not None else None,
            "date": row.get("date"),
        }

    return results