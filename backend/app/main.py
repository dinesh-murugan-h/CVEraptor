from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.nvd_service import get_nvd_cve, search_nvd_cves
from app.services.epss_service import get_epss, get_epss_batch
from app.services.kev_service import get_kev_status, get_kev_batch

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


@app.get("/api/cves")
def list_cves(
    results_per_page: int = 25,
    page: int = 1,
    keyword: str | None = None,
):
    results_per_page = min(max(results_per_page, 1), 100)
    page = max(page, 1)

    nvd_data = search_nvd_cves(
        results_per_page=results_per_page,
        page=page,
        keyword=keyword,
    )

    nvd_items = nvd_data.get("items", [])
    cve_ids = [item.get("id") for item in nvd_items if item.get("id")]

    epss_map = get_epss_batch(cve_ids)
    kev_map = get_kev_batch(cve_ids)

    enriched_items = []

    for item in nvd_items:
        cve_id = item.get("id")

        enriched_items.append({
            "cve_id": cve_id,
            "nvd": item,
            "epss": epss_map.get(cve_id, {"found": False}),
            "kev": kev_map.get(cve_id, {"found": False}),
        })

    return {
        "source": "nvd",
        "results_per_page": results_per_page,
        "page": nvd_data.get("page", page),
        "total_results": nvd_data.get("total_results", 0),
        "total_pages": nvd_data.get("total_pages", 0),
        "items": enriched_items,
        "error": nvd_data.get("error"),
    }