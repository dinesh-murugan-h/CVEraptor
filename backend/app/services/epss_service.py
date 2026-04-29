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