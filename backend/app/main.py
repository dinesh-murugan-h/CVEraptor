from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.nvd_service import get_nvd_cve, search_nvd_cves
from app.services.epss_service import get_epss, get_epss_batch
from app.services.kev_service import (
    get_kev_status,
    get_kev_batch,
    get_kev_cve_ids,
    load_kev_catalog,
)
from app.services.vulnrichment_service import (
    get_vulnrichment,
    get_vulnrichment_batch,
    query_ssvc_index,
)

app = FastAPI(title="cveraptor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_cve_id(value: str | None) -> bool:
    if not value:
        return False

    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", value.upper().strip()))


def clean_filter_value(value: str | None, allowed_values: set[str]) -> str:
    if not value:
        return "all"

    cleaned = value.strip().lower()

    if cleaned not in allowed_values:
        return "all"

    return cleaned


def normalise_keyword(keyword: str | None) -> str:
    if not keyword:
        return ""

    return keyword.strip()


def cve_sort_key(cve_id: str):
    try:
        _, year, number = cve_id.split("-")
        return int(year), int(number)
    except Exception:
        return 0, 0


def filters_are_active(
    kev: str,
    exploitation: str,
    automatable: str,
    technical_impact: str,
) -> bool:
    return any([
        kev != "all",
        exploitation != "all",
        automatable != "all",
        technical_impact != "all",
    ])


def ssvc_index_filters_are_active(
    exploitation: str,
    automatable: str,
    technical_impact: str,
) -> bool:
    """
    These filters can be answered from the CISA Vulnrichment SSVC index.

    no_ssvc cannot be answered from the SSVC index because the index only
    contains records that have SSVC data.
    """
    return any([
        exploitation not in ["all", "no_ssvc"],
        automatable not in ["all", "no_ssvc"],
        technical_impact not in ["all", "no_ssvc"],
    ])


def get_ssvc_value(item: dict, field: str) -> str:
    vulnrichment = item.get("vulnrichment", {})
    ssvc = vulnrichment.get("ssvc", {})

    if not ssvc or not ssvc.get("found"):
        return "no_ssvc"

    value = ssvc.get(field)

    if value is None:
        return "no_ssvc"

    return str(value).strip().lower()


def item_passes_filters(
    item: dict,
    kev: str,
    exploitation: str,
    automatable: str,
    technical_impact: str,
) -> bool:
    kev_found = bool(item.get("kev", {}).get("found"))

    if kev == "yes" and not kev_found:
        return False

    if kev == "no" and kev_found:
        return False

    if exploitation != "all":
        if get_ssvc_value(item, "exploitation") != exploitation:
            return False

    if automatable != "all":
        if get_ssvc_value(item, "automatable") != automatable:
            return False

    if technical_impact != "all":
        if get_ssvc_value(item, "technical_impact") != technical_impact:
            return False

    return True


def get_nvd_batch_by_ids(cve_ids: list[str]) -> dict[str, dict]:
    if not cve_ids:
        return {}

    results = {}
    max_workers = min(8, len(cve_ids))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(get_nvd_cve, cve_id): cve_id
            for cve_id in cve_ids
        }

        for future in as_completed(future_map):
            cve_id = future_map[future]

            try:
                results[cve_id] = future.result()
            except Exception as error:
                results[cve_id] = {
                    "found": False,
                    "source": "nvd",
                    "id": cve_id,
                    "error": str(error),
                }

    return results


def enrich_nvd_items(nvd_items: list[dict]) -> list[dict]:
    cve_ids = [
        item.get("id").upper().strip()
        for item in nvd_items
        if item.get("id")
    ]

    epss_map = get_epss_batch(cve_ids)
    kev_map = get_kev_batch(cve_ids)
    vulnrichment_map = get_vulnrichment_batch(cve_ids)

    enriched_items = []

    for item in nvd_items:
        cve_id = item.get("id")

        if cve_id:
            cve_id = cve_id.upper().strip()

        enriched_items.append({
            "cve_id": cve_id,
            "nvd": item,
            "epss": epss_map.get(cve_id, {"found": False}),
            "kev": kev_map.get(cve_id, {"found": False}),
            "vulnrichment": vulnrichment_map.get(cve_id, {"found": False}),
        })

    return enriched_items


def hydrate_cve_ids(
    cve_ids: list[str],
    override_vulnrichment_map: dict[str, dict] | None = None,
) -> list[dict]:
    if not cve_ids:
        return []

    cve_ids = [
        cve_id.upper().strip()
        for cve_id in cve_ids
        if cve_id
    ]

    nvd_map = get_nvd_batch_by_ids(cve_ids)
    epss_map = get_epss_batch(cve_ids)
    kev_map = get_kev_batch(cve_ids)

    if override_vulnrichment_map is None:
        vulnrichment_map = get_vulnrichment_batch(cve_ids)
    else:
        vulnrichment_map = override_vulnrichment_map

        missing = [
            cve_id
            for cve_id in cve_ids
            if cve_id not in vulnrichment_map
        ]

        if missing:
            fetched = get_vulnrichment_batch(missing)
            vulnrichment_map = {
                **vulnrichment_map,
                **fetched,
            }

    items = []

    for cve_id in cve_ids:
        nvd_data = nvd_map.get(
            cve_id,
            {
                "found": False,
                "source": "nvd",
                "id": cve_id,
                "message": "No NVD data loaded",
            },
        )

        items.append({
            "cve_id": cve_id,
            "nvd": nvd_data,
            "epss": epss_map.get(cve_id, {"found": False}),
            "kev": kev_map.get(cve_id, {"found": False}),
            "vulnrichment": vulnrichment_map.get(cve_id, {"found": False}),
        })

    return items


def paginate_ids(cve_ids: list[str], page: int, results_per_page: int) -> tuple[list[str], int]:
    total_results = len(cve_ids)

    if total_results == 0:
        return [], 0

    total_pages = (total_results + results_per_page - 1) // results_per_page

    start = (page - 1) * results_per_page
    end = page * results_per_page

    return cve_ids[start:end], total_pages


def fallback_scan_filter(
    keyword: str | None,
    results_per_page: int,
    page: int,
    kev: str,
    exploitation: str,
    automatable: str,
    technical_impact: str,
    max_scan_pages: int,
):
    """
    Fallback for filters that cannot be globally indexed, mainly:
    - no_ssvc
    - KEV = no without any SSVC indexed condition

    This remains partial because NVD does not natively filter by CISA SSVC.
    """
    scan_page_size = 100
    all_filtered_items = []
    candidates_scanned = 0
    pages_scanned = 0
    nvd_total_results = 0
    nvd_total_pages = 0
    error = None

    for scan_page in range(1, max_scan_pages + 1):
        nvd_data = search_nvd_cves(
            results_per_page=scan_page_size,
            page=scan_page,
            keyword=keyword or None,
        )

        if nvd_data.get("error"):
            error = nvd_data.get("error")
            break

        nvd_total_results = nvd_data.get("total_results", 0)
        nvd_total_pages = nvd_data.get("total_pages", 0)
        nvd_items = nvd_data.get("items", [])

        if not nvd_items:
            break

        pages_scanned = scan_page
        candidates_scanned += len(nvd_items)

        enriched_items = enrich_nvd_items(nvd_items)

        for item in enriched_items:
            if item_passes_filters(
                item=item,
                kev=kev,
                exploitation=exploitation,
                automatable=automatable,
                technical_impact=technical_impact,
            ):
                all_filtered_items.append(item)

        if nvd_total_pages and scan_page >= nvd_total_pages:
            break

    total_results = len(all_filtered_items)
    total_pages = (
        (total_results + results_per_page - 1) // results_per_page
        if total_results > 0
        else 0
    )

    start = (page - 1) * results_per_page
    end = page * results_per_page

    page_items = all_filtered_items[start:end]

    more_results_may_exist = bool(
        nvd_total_pages and pages_scanned < nvd_total_pages
    )

    return {
        "source": "nvd",
        "mode": "fallback_scan_filter",
        "keyword": keyword or None,
        "results_per_page": results_per_page,
        "page": page,
        "total_results": total_results,
        "total_pages": total_pages,
        "nvd_total_results": nvd_total_results,
        "items": page_items,
        "error": error,
        "scan": {
            "active": True,
            "source": "nvd_scan",
            "pages_scanned": pages_scanned,
            "max_scan_pages": max_scan_pages,
            "candidates_scanned": candidates_scanned,
            "filtered_total_is_partial": more_results_may_exist,
            "more_results_may_exist": more_results_may_exist,
        },
    }


@app.get("/")
def home():
    return {
        "message": "cveraptor backend is running",
    }


@app.get("/api/cve/{cve_id}")
def lookup_cve(cve_id: str):
    cve_id = cve_id.upper().strip()

    nvd_data = get_nvd_cve(cve_id)
    epss_data = get_epss(cve_id)
    kev_data = get_kev_status(cve_id)
    vulnrichment_data = get_vulnrichment(cve_id)

    return {
        "cve_id": cve_id,
        "nvd": nvd_data,
        "epss": epss_data,
        "kev": kev_data,
        "vulnrichment": vulnrichment_data,
    }


@app.get("/api/cves")
def list_cves(
    results_per_page: int = 25,
    page: int = 1,
    keyword: str | None = None,
    kev: str = "all",
    exploitation: str = "all",
    automatable: str = "all",
    technical_impact: str = "all",
    max_scan_pages: int = 6,
):
    results_per_page = min(max(results_per_page, 1), 100)
    page = max(page, 1)
    max_scan_pages = min(max(max_scan_pages, 1), 20)

    keyword = normalise_keyword(keyword)

    kev = clean_filter_value(kev, {"all", "yes", "no"})
    exploitation = clean_filter_value(exploitation, {"all", "none", "poc", "active", "no_ssvc"})
    automatable = clean_filter_value(automatable, {"all", "yes", "no", "no_ssvc"})
    technical_impact = clean_filter_value(technical_impact, {"all", "partial", "total", "no_ssvc"})

    active_filters = filters_are_active(
        kev=kev,
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
    )

    filters_payload = {
        "kev": kev,
        "exploitation": exploitation,
        "automatable": automatable,
        "technical_impact": technical_impact,
    }

    # Direct CVE test path.
    # Example: keyword=CVE-2026-32202 + KEV only + Exploitation active.
    if is_cve_id(keyword):
        cve_id = keyword.upper().strip()
        item = hydrate_cve_ids([cve_id])[0]

        if active_filters and not item_passes_filters(
            item=item,
            kev=kev,
            exploitation=exploitation,
            automatable=automatable,
            technical_impact=technical_impact,
        ):
            items = []
        else:
            items = [item]

        return {
            "source": "direct_cve",
            "mode": "direct_cve_filter",
            "keyword": keyword,
            "filters": filters_payload,
            "results_per_page": results_per_page,
            "page": 1,
            "total_results": len(items),
            "total_pages": 1 if items else 0,
            "items": items,
            "error": None,
            "scan": {
                "active": False,
                "source": "direct_cve",
                "pages_scanned": 0,
                "candidates_scanned": 1,
                "filtered_total_is_partial": False,
                "more_results_may_exist": False,
            },
        }

    # Normal path when no dropdown filters are active.
    if not active_filters:
        nvd_data = search_nvd_cves(
            results_per_page=results_per_page,
            page=page,
            keyword=keyword or None,
        )

        nvd_items = nvd_data.get("items", [])
        enriched_items = enrich_nvd_items(nvd_items)

        return {
            "source": "nvd",
            "mode": "unfiltered",
            "keyword": keyword or None,
            "filters": filters_payload,
            "results_per_page": results_per_page,
            "page": nvd_data.get("page", page),
            "total_results": nvd_data.get("total_results", 0),
            "total_pages": nvd_data.get("total_pages", 0),
            "items": enriched_items,
            "error": nvd_data.get("error"),
            "scan": {
                "active": False,
                "source": "nvd",
                "pages_scanned": 1,
                "candidates_scanned": len(enriched_items),
                "filtered_total_is_partial": False,
                "more_results_may_exist": False,
            },
        }

    # Global SSVC path.
    # This handles exploitation=active/poc/none, automatable=yes/no,
    # and technical_impact=partial/total without relying on NVD scanning.
    if ssvc_index_filters_are_active(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
    ):
        ssvc_result = query_ssvc_index(
            keyword=keyword or None,
            exploitation=exploitation if exploitation != "no_ssvc" else "all",
            automatable=automatable if automatable != "no_ssvc" else "all",
            technical_impact=technical_impact if technical_impact != "no_ssvc" else "all",
        )

        if not ssvc_result.get("found"):
            return {
                "source": "cisa_vulnrichment_index",
                "mode": "ssvc_index_filter",
                "keyword": keyword or None,
                "filters": filters_payload,
                "results_per_page": results_per_page,
                "page": page,
                "total_results": 0,
                "total_pages": 0,
                "items": [],
                "error": ssvc_result.get("error"),
                "scan": {
                    "active": True,
                    "source": "cisa_vulnrichment_index",
                    "pages_scanned": 0,
                    "candidates_scanned": 0,
                    "filtered_total_is_partial": False,
                    "more_results_may_exist": False,
                },
            }

        ssvc_items = ssvc_result.get("items", [])
        kev_map = load_kev_catalog()

        filtered_ssvc_items = []

        for item in ssvc_items:
            cve_id = item.get("cve_id")
            is_kev = cve_id in kev_map

            if kev == "yes" and not is_kev:
                continue

            if kev == "no" and is_kev:
                continue

            filtered_ssvc_items.append(item)

        cve_ids = [item["cve_id"] for item in filtered_ssvc_items]
        cve_ids.sort(key=cve_sort_key, reverse=True)

        page_ids, total_pages = paginate_ids(cve_ids, page, results_per_page)

        override_vulnrichment_map = {
            item["cve_id"]: item["vulnrichment"]
            for item in filtered_ssvc_items
            if item["cve_id"] in page_ids
        }

        page_items = hydrate_cve_ids(
            cve_ids=page_ids,
            override_vulnrichment_map=override_vulnrichment_map,
        )

        return {
            "source": "cisa_vulnrichment_index",
            "mode": "ssvc_index_filter",
            "keyword": keyword or None,
            "filters": filters_payload,
            "results_per_page": results_per_page,
            "page": page,
            "total_results": len(cve_ids),
            "total_pages": total_pages,
            "items": page_items,
            "error": None,
            "scan": {
                "active": True,
                "source": "cisa_vulnrichment_index",
                "pages_scanned": 1,
                "candidates_scanned": ssvc_result.get("total_results", 0),
                "filtered_total_is_partial": False,
                "more_results_may_exist": False,
            },
        }

    # Global KEV path.
    # This handles KEV only correctly using the CISA KEV catalogue directly.
    if kev == "yes":
        cve_ids = get_kev_cve_ids(keyword=keyword or None)

        page_ids, total_pages = paginate_ids(cve_ids, page, results_per_page)
        page_items = hydrate_cve_ids(page_ids)

        return {
            "source": "cisa_kev",
            "mode": "kev_catalog_filter",
            "keyword": keyword or None,
            "filters": filters_payload,
            "results_per_page": results_per_page,
            "page": page,
            "total_results": len(cve_ids),
            "total_pages": total_pages,
            "items": page_items,
            "error": None,
            "scan": {
                "active": True,
                "source": "cisa_kev_catalog",
                "pages_scanned": 1,
                "candidates_scanned": len(cve_ids),
                "filtered_total_is_partial": False,
                "more_results_may_exist": False,
            },
        }

    # Fallback for no_ssvc / kev=no cases.
    fallback = fallback_scan_filter(
        keyword=keyword or None,
        results_per_page=results_per_page,
        page=page,
        kev=kev,
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        max_scan_pages=max_scan_pages,
    )

    fallback["filters"] = filters_payload
    return fallback