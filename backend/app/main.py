from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.nvd_service import get_nvd_cve, get_latest_nvd_cves
from app.services.epss_service import get_epss
from app.services.kev_service import get_kev_status

app = FastAPI(title="cveraptor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "cveraptor backend is running"
    }


@app.get("/api/cve/{cve_id}")
def lookup_cve(cve_id: str):
    cve_id = cve_id.upper().strip()

    nvd_data = get_nvd_cve(cve_id)
    epss_data = get_epss(cve_id)
    kev_data = get_kev_status(cve_id)

    return {
        "cve_id": cve_id,
        "nvd": nvd_data,
        "epss": epss_data,
        "kev": kev_data,
    }

@app.get("/api/cves/latest")
def latest_cves(days: int = 7, limit: int = 20):
    limit = min(max(limit, 1), 50)
    days = min(max(days, 1), 30)

    latest_data = get_latest_nvd_cves(days=days, limit=limit)

    enriched_items = []

    for item in latest_data.get("items", []):
        cve_id = item.get("id")

        epss_data = get_epss(cve_id) if cve_id else {"found": False}
        kev_data = get_kev_status(cve_id) if cve_id else {"found": False}

        enriched_items.append({
            "cve_id": cve_id,
            "nvd": item,
            "epss": epss_data,
            "kev": kev_data,
        })

    return {
        "source": "nvd",
        "days": days,
        "limit": limit,
        "total_results": latest_data.get("total_results"),
        "items": enriched_items,
        "error": latest_data.get("error"),
    }