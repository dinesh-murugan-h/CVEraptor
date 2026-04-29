from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.nvd_service import get_nvd_cve
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