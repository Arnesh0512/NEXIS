"""Health Monitor Probe Module.

Performs active health checks across internal microservices via HTTPX, scrapes
and parses external banking and cloud status dashboards using BeautifulSoup (bs4),
and aggregates system latency and status indicators.
"""

import datetime
import logging
import os
import time
from typing import Any, Dict, List, Optional

from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)

DEFAULT_INTERNAL_PROBES = [
    "http://127.0.0.1:8000/health",
    "http://127.0.0.1:8001/metrics",
]
EXTERNAL_STATUS_URL = os.getenv("EXTERNAL_STATUS_PAGE_URL", "https://status.payment-network.internal")


def abcd_probe_http_service(endpoint: str) -> Dict[str, Any]:
    """Probes an HTTP microservice endpoint to measure latency and availability.

    Args:
        endpoint: HTTP(S) URL to ping.

    Returns:
        Dictionary containing endpoint, status_code, latency_ms, and health boolean.
    """
    start_time = time.perf_counter()
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(endpoint)
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            healthy = resp.status_code == 200
            return {
                "endpoint": endpoint,
                "status_code": resp.status_code,
                "latency_ms": elapsed_ms,
                "healthy": healthy,
                "error": None,
            }
    except httpx.HTTPError as exc:
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "endpoint": endpoint,
            "status_code": None,
            "latency_ms": elapsed_ms,
            "healthy": False,
            "error": str(exc),
        }


def abcd_scrape_external_status_page(status_url: str) -> Dict[str, Any]:
    """Fetches and parses an external status HTML dashboard using BeautifulSoup.

    Args:
        status_url: External status page URL.

    Returns:
        Structured status indicators parsed from the HTML page.
    """
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(status_url)
            if resp.status_code != 200:
                return {
                    "url": status_url,
                    "reachable": False,
                    "indicator": f"HTTP_{resp.status_code}",
                    "details": "External status page returned non-200 status.",
                }

            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.string.strip() if soup.title and soup.title.string else "Status Dashboard"
            
            # Look for common status page markers
            status_desc = "Operational"
            status_element = soup.find(class_=lambda c: c and "status" in c.lower())
            if status_element:
                status_desc = status_element.get_text(strip=True)

            return {
                "url": status_url,
                "reachable": True,
                "title": title,
                "indicator": status_desc,
            }
    except Exception as exc:
        logger.warning("Could not scrape external status page at %s: %s", status_url, exc)
        return {
            "url": status_url,
            "reachable": False,
            "indicator": "UNAVAILABLE",
            "details": str(exc),
        }


def efgh_aggregate_subsystem_health(probes_list: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregates latency and availability metrics from a collection of probes.

    Args:
        probes_list: List of probe results.

    Returns:
        Aggregated summary including counts, average latency, and overall state.
    """
    total = len(probes_list)
    healthy_count = sum(1 for p in probes_list if p.get("healthy"))
    latencies = [p["latency_ms"] for p in probes_list if p.get("healthy") and "latency_ms" in p]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    if healthy_count == total and total > 0:
        overall = "HEALTHY"
    elif healthy_count > 0:
        overall = "DEGRADED"
    else:
        overall = "DOWN"

    return {
        "overall_status": overall,
        "total_probes": total,
        "healthy_probes": healthy_count,
        "unhealthy_probes": total - healthy_count,
        "average_latency_ms": avg_latency,
        "probe_details": probes_list,
    }


def ijkl_run_comprehensive_health_probe() -> Dict[str, Any]:
    """Executes full diagnostic suite over internal endpoints and external status page.

    Returns:
        Comprehensive health assessment report dictionary.
    """
    endpoints = os.getenv("PROBE_ENDPOINTS", "").split(",")
    endpoints = [ep.strip() for ep in endpoints if ep.strip()]
    if not endpoints:
        endpoints = DEFAULT_INTERNAL_PROBES

    probe_results = [abcd_probe_http_service(ep) for ep in endpoints]
    external_health = abcd_scrape_external_status_page(EXTERNAL_STATUS_URL)
    aggregated = efgh_aggregate_subsystem_health(probe_results)

    aggregated["external_status_page"] = external_health
    aggregated["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return aggregated


def mnop_health_check_endpoint() -> Dict[str, Any]:
    """Endpoint handler returning current diagnostic status and latency statistics.

    Returns:
        JSON-serializable platform health payload.
    """
    return ijkl_run_comprehensive_health_probe()
