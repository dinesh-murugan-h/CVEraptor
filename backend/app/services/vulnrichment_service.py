import io
import json
import re
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests


CVE_API_URL = "https://cveawg.mitre.org/api/cve"
VULNRICHMENT_RAW_URL = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
VULNRICHMENT_ZIP_URL = "https://github.com/cisagov/vulnrichment/archive/refs/heads/develop.zip"

CACHE_TTL_SECONDS = 3600
SSVC_INDEX_TTL_SECONDS = 21600

_cache = {
    "loaded_at": {},
    "data": {},
}

_ssvc_index_cache = {
    "loaded_at": 0,
    "data": {},
    "error": None,
}

_ssvc_index_lock = threading.Lock()


def normalise_cve_id(cve_id: str) -> str:
    cve_id = cve_id.upper().strip()

    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        raise ValueError("Invalid CVE ID format")

    return cve_id


def is_cve_id(value: str | None) -> bool:
    if not value:
        return False

    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", value.upper().strip()))


def cve_sort_key(cve_id: str):
    try:
        _, year, number = cve_id.split("-")
        return int(year), int(number)
    except Exception:
        return 0, 0


def cve_to_vulnrichment_path(cve_id: str) -> str:
    match = re.match(r"^CVE-(\d{4})-(\d+)$", cve_id)

    if not match:
        raise ValueError("Invalid CVE ID format")

    year = match.group(1)
    number = int(match.group(2))
    bucket = f"{number // 1000}xxx"

    return f"{year}/{bucket}/{cve_id}.json"


def get_cached(cve_id: str):
    loaded_at = _cache["loaded_at"].get(cve_id)
    data = _cache["data"].get(cve_id)

    if not loaded_at or not data:
        return None

    if time.time() - loaded_at > CACHE_TTL_SECONDS:
        _cache["loaded_at"].pop(cve_id, None)
        _cache["data"].pop(cve_id, None)
        return None

    return data


def set_cached(cve_id: str, data: dict):
    _cache["loaded_at"][cve_id] = time.time()
    _cache["data"][cve_id] = data


def fetch_from_cve_api(cve_id: str) -> dict | None:
    response = requests.get(
        f"{CVE_API_URL}/{cve_id}",
        timeout=20,
        headers={"Accept": "application/json"},
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def fetch_from_vulnrichment_github(cve_id: str) -> dict | None:
    path = cve_to_vulnrichment_path(cve_id)

    response = requests.get(
        f"{VULNRICHMENT_RAW_URL}/{path}",
        timeout=20,
        headers={"Accept": "application/json"},
    )

    if response.status_code == 404:
        return None

    response.raise_for_status()
    return response.json()


def fetch_cve_record(cve_id: str) -> tuple[dict | None, str | None]:
    try:
        data = fetch_from_cve_api(cve_id)

        if data:
            return data, "cve_services_api"
    except requests.exceptions.RequestException:
        pass

    try:
        data = fetch_from_vulnrichment_github(cve_id)

        if data:
            return data, "cisa_vulnrichment_github"
    except requests.exceptions.RequestException:
        pass

    return None, None


def find_cisa_adp_container(record: dict) -> dict | None:
    containers = record.get("containers", {})
    adp_containers = containers.get("adp", [])

    if not isinstance(adp_containers, list):
        return None

    for container in adp_containers:
        title = (container.get("title") or "").lower()
        provider = container.get("providerMetadata", {})
        short_name = (provider.get("shortName") or "").lower()

        if title == "cisa adp vulnrichment":
            return container

        if "cisa" in short_name:
            return container

        if "cisa" in title and "vulnrichment" in title:
            return container

    return None


def extract_affected_from_record(record: dict) -> dict:
    cna = record.get("containers", {}).get("cna", {})
    affected = cna.get("affected", [])

    if not isinstance(affected, list):
        affected = []

    items = []

    for entry in affected:
        if not isinstance(entry, dict):
            continue

        vendor = entry.get("vendor") or "Unknown"
        product = entry.get("product") or "Unknown"

        versions = []

        for version_entry in entry.get("versions", []) or []:
            if not isinstance(version_entry, dict):
                continue

            version_text = version_entry.get("version")
            status = version_entry.get("status")
            less_than = version_entry.get("lessThan")
            less_than_or_equal = version_entry.get("lessThanOrEqual")

            parts = []

            if version_text:
                parts.append(str(version_text))

            if less_than:
                parts.append(f"< {less_than}")

            if less_than_or_equal:
                parts.append(f"<= {less_than_or_equal}")

            if status:
                parts.append(f"({status})")

            if parts:
                versions.append(" ".join(parts))

        items.append({
            "vendor": vendor,
            "product": product,
            "versions": versions,
        })

    vendors = sorted({
        item["vendor"]
        for item in items
        if item.get("vendor") and item.get("vendor") != "Unknown"
    })

    products = sorted({
        item["product"]
        for item in items
        if item.get("product") and item.get("product") != "Unknown"
    })

    return {
        "found": bool(items),
        "vendors": vendors,
        "products": products,
        "items": items,
    }


def extract_ssvc_from_adp(adp: dict) -> dict:
    metrics = adp.get("metrics", [])

    if not isinstance(metrics, list):
        return {
            "found": False,
            "message": "No metrics array found in CISA ADP container",
        }

    for metric in metrics:
        other = metric.get("other", {})

        if not isinstance(other, dict):
            continue

        if other.get("type") != "ssvc":
            continue

        content = other.get("content", {})
        options = content.get("options", [])

        ssvc = {
            "found": True,
            "exploitation": None,
            "automatable": None,
            "technical_impact": None,
            "timestamp": content.get("timestamp"),
            "id": content.get("id"),
            "role": content.get("role"),
            "version": content.get("version"),
            "raw_options": options,
        }

        for option in options:
            if not isinstance(option, dict):
                continue

            if "Exploitation" in option:
                ssvc["exploitation"] = option.get("Exploitation")

            if "Automatable" in option:
                ssvc["automatable"] = option.get("Automatable")

            if "Technical Impact" in option:
                ssvc["technical_impact"] = option.get("Technical Impact")

        return ssvc

    return {
        "found": False,
        "message": "No SSVC block found in CISA ADP container",
    }


def extract_kev_from_adp(adp: dict) -> dict:
    metrics = adp.get("metrics", [])

    if not isinstance(metrics, list):
        return {"found": False}

    for metric in metrics:
        other = metric.get("other", {})

        if not isinstance(other, dict):
            continue

        if other.get("type") != "kev":
            continue

        content = other.get("content", {})

        return {
            "found": True,
            "date_added": content.get("dateAdded"),
            "reference": content.get("reference"),
        }

    return {"found": False}


def extract_cisa_cvss_from_adp(adp: dict) -> dict:
    metrics = adp.get("metrics", [])

    if not isinstance(metrics, list):
        return {"found": False}

    for metric in metrics:
        for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]:
            if key in metric:
                cvss = metric.get(key, {})

                return {
                    "found": True,
                    "version": cvss.get("version"),
                    "base_score": cvss.get("baseScore"),
                    "base_severity": cvss.get("baseSeverity"),
                    "vector": cvss.get("vectorString"),
                    "source_key": key,
                }

    return {"found": False}


def build_vulnrichment_result(
    cve_id: str,
    record: dict,
    record_source: str,
) -> dict:
    affected = extract_affected_from_record(record)
    adp = find_cisa_adp_container(record)

    if not adp:
        return {
            "found": False,
            "source": "cisa_vulnrichment",
            "record_source": record_source,
            "message": "CVE record found, but no CISA ADP Vulnrichment container found",
            "affected": affected,
        }

    provider = adp.get("providerMetadata", {})

    return {
        "found": True,
        "source": "cisa_vulnrichment",
        "record_source": record_source,
        "title": adp.get("title"),
        "provider": {
            "short_name": provider.get("shortName"),
            "org_id": provider.get("orgId"),
            "date_updated": provider.get("dateUpdated"),
        },
        "affected": affected,
        "ssvc": extract_ssvc_from_adp(adp),
        "kev_adp": extract_kev_from_adp(adp),
        "cisa_cvss": extract_cisa_cvss_from_adp(adp),
    }


def get_vulnrichment(cve_id: str) -> dict:
    try:
        cve_id = normalise_cve_id(cve_id)
    except ValueError as error:
        return {
            "found": False,
            "source": "cisa_vulnrichment",
            "error": str(error),
        }

    cached = get_cached(cve_id)

    if cached:
        return cached

    record, record_source = fetch_cve_record(cve_id)

    if not record:
        result = {
            "found": False,
            "source": "cisa_vulnrichment",
            "message": "No CVE record or CISA Vulnrichment data found",
            "affected": {
                "found": False,
                "vendors": [],
                "products": [],
                "items": [],
            },
        }

        set_cached(cve_id, result)
        return result

    result = build_vulnrichment_result(
        cve_id=cve_id,
        record=record,
        record_source=record_source,
    )

    set_cached(cve_id, result)
    return result


def get_vulnrichment_batch(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}

    unique_cve_ids = []
    seen = set()

    for cve_id in cve_ids:
        if not cve_id:
            continue

        cve_id = cve_id.upper().strip()

        if cve_id not in seen:
            unique_cve_ids.append(cve_id)
            seen.add(cve_id)

    results: dict[str, dict[str, Any]] = {}
    missing_cve_ids = []

    for cve_id in unique_cve_ids:
        cached = get_cached(cve_id)

        if cached:
            results[cve_id] = cached
        else:
            missing_cve_ids.append(cve_id)

    if not missing_cve_ids:
        return results

    max_workers = min(12, len(missing_cve_ids))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(get_vulnrichment, cve_id): cve_id
            for cve_id in missing_cve_ids
        }

        for future in as_completed(future_map):
            cve_id = future_map[future]

            try:
                results[cve_id] = future.result()
            except Exception as error:
                results[cve_id] = {
                    "found": False,
                    "source": "cisa_vulnrichment",
                    "error": str(error),
                }

    return results


def get_ssvc_index(force_refresh: bool = False) -> dict[str, dict]:
    """
    Build a searchable SSVC index from the CISA Vulnrichment repo.

    First SSVC dropdown use may take a little while. After that, the index
    stays cached in memory.
    """
    now = time.time()

    with _ssvc_index_lock:
        if (
            not force_refresh
            and _ssvc_index_cache["data"]
            and now - _ssvc_index_cache["loaded_at"] < SSVC_INDEX_TTL_SECONDS
        ):
            return _ssvc_index_cache["data"]

    response = requests.get(VULNRICHMENT_ZIP_URL, timeout=180)
    response.raise_for_status()

    index: dict[str, dict] = {}

    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        for name in zip_file.namelist():
            filename = name.rsplit("/", 1)[-1]

            if not filename.endswith(".json"):
                continue

            cve_id = filename[:-5].upper().strip()

            if not is_cve_id(cve_id):
                continue

            try:
                with zip_file.open(name) as file:
                    record = json.loads(file.read().decode("utf-8", errors="replace"))

                result = build_vulnrichment_result(
                    cve_id=cve_id,
                    record=record,
                    record_source="cisa_vulnrichment_zip_index",
                )

                ssvc = result.get("ssvc", {})

                if not ssvc or not ssvc.get("found"):
                    continue

                index[cve_id] = {
                    "cve_id": cve_id,
                    "vulnrichment": result,
                    "ssvc": ssvc,
                    "affected": result.get("affected", {}),
                }

                set_cached(cve_id, result)

            except Exception:
                continue

    with _ssvc_index_lock:
        _ssvc_index_cache["loaded_at"] = time.time()
        _ssvc_index_cache["data"] = index
        _ssvc_index_cache["error"] = None

    return index


def query_ssvc_index(
    keyword: str | None = None,
    exploitation: str = "all",
    automatable: str = "all",
    technical_impact: str = "all",
) -> dict:
    try:
        index = get_ssvc_index()
    except Exception as error:
        return {
            "found": False,
            "source": "cisa_vulnrichment_index",
            "error": str(error),
            "total_results": 0,
            "items": [],
        }

    keyword = keyword.strip().lower() if keyword else ""
    matched_items = []

    for cve_id, item in index.items():
        ssvc = item.get("ssvc", {})
        affected = item.get("affected", {})

        if exploitation != "all":
            if str(ssvc.get("exploitation") or "").strip().lower() != exploitation:
                continue

        if automatable != "all":
            if str(ssvc.get("automatable") or "").strip().lower() != automatable:
                continue

        if technical_impact != "all":
            if str(ssvc.get("technical_impact") or "").strip().lower() != technical_impact:
                continue

        if keyword:
            searchable = " ".join([
                cve_id,
                " ".join(affected.get("vendors", []) or []),
                " ".join(affected.get("products", []) or []),
            ]).lower()

            if keyword not in searchable:
                continue

        matched_items.append(item)

    matched_items.sort(
        key=lambda item: cve_sort_key(item.get("cve_id", "")),
        reverse=True,
    )

    return {
        "found": True,
        "source": "cisa_vulnrichment_index",
        "total_results": len(matched_items),
        "items": matched_items,
    }