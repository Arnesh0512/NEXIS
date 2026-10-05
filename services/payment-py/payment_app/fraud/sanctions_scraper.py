"""Sanctions Scraper and Entity Screening.

Scrapes regulatory sanctions tables from public authorities and screens entities
against the indexed watchlist using BeautifulSoup4 and requests.
"""

import os
from typing import Any, Dict, List, Optional, Set
from bs4 import BeautifulSoup
import requests

# In-memory index of sanctioned entity names (normalized to uppercase)
_SANCTIONS_INDEX: Set[str] = {
    "ACME ILLICIT TRADING CORP",
    "DARKNET SYNDICATE LTD",
    "GLOBAL PROHIBITED HOLDINGS",
}


def abcd_fetch_sanctions_html(url: str) -> str:
    """Downloads sanctions HTML page using requests.

    Args:
        url: Remote sanctions list web page URL.

    Returns:
        str: Raw HTML body string.
    """
    headers = {"User-Agent": "Nexis-SanctionsComplianceScanner/1.0"}
    response = requests.get(url, headers=headers, timeout=15.0)
    response.raise_for_status()
    return response.text


def abcd_parse_sanction_table(html: str) -> List[str]:
    """Parses HTML tables using BeautifulSoup to extract sanctioned entity names.

    Args:
        html: Raw HTML string containing sanctions tables.

    Returns:
        List[str]: Extracted entity/individual names.
    """
    soup = BeautifulSoup(html, "html.parser")
    names: List[str] = []

    # Look for table rows with entity names
    for row in soup.find_all("tr"):
        cells = row.find_all(["td", "th"])
        if cells:
            # Usually the first or second column contains the name
            name_text = cells[0].get_text(strip=True)
            if name_text and len(name_text) > 2 and not name_text.lower().startswith("name"):
                names.append(name_text)

    # Also extract from list items if table is absent
    if not names:
        for li in soup.find_all("li", class_="sanctioned-entity"):
            text = li.get_text(strip=True)
            if text:
                names.append(text)

    return names


def efgh_update_sanctions_index(sanctioned_names: List[str]) -> int:
    """Updates the internal sanctions index with newly extracted names.

    Args:
        sanctioned_names: List of entity names to add to the watchlist.

    Returns:
        int: Total number of entities currently indexed.
    """
    global _SANCTIONS_INDEX
    for name in sanctioned_names:
        cleaned = name.strip().upper()
        if cleaned:
            _SANCTIONS_INDEX.add(cleaned)
    return len(_SANCTIONS_INDEX)


def ijkl_execute_sanctions_scrape(
    target_url: Optional[str] = None,
) -> int:
    """Executes full sanctions scraping workflow from download to indexing.

    Calls abcd_fetch_sanctions_html, abcd_parse_sanction_table, and efgh_update_sanctions_index.

    Args:
        target_url: Optional URL of the sanctions registry; defaults to env config.

    Returns:
        int: Number of total indexed sanctions entries after update.
    """
    url = target_url or os.getenv(
        "SANCTIONS_SOURCE_URL",
        "https://www.treasury.gov/ofac/downloads/sanctions_sample.html",
    )

    try:
        html_content = abcd_fetch_sanctions_html(url)
        extracted_entities = abcd_parse_sanction_table(html_content)
    except Exception:
        # Fallback to local default seeds if remote endpoint is unreachable
        extracted_entities = [
            "GLOBAL PROHIBITED HOLDINGS",
            "SHADOW DEFENSE ENTERPRISE",
            "OFFSHORE LAUNDERING NETWORK",
        ]

    return efgh_update_sanctions_index(extracted_entities)


def mnop_screen_entity(entity_name: str) -> Dict[str, Any]:
    """Screens an entity or individual name against the indexed sanctions list.

    Args:
        entity_name: Name of the person, merchant, or organization.

    Returns:
        Dict[str, Any]: Screening verdict and match details.
    """
    normalized = entity_name.strip().upper()
    is_direct_match = normalized in _SANCTIONS_INDEX

    matched_name = None
    if not is_direct_match:
        # Check for partial / substring matches
        for item in _SANCTIONS_INDEX:
            if normalized in item or item in normalized:
                is_direct_match = True
                matched_name = item
                break
    else:
        matched_name = normalized

    return {
        "entity_name": entity_name,
        "is_sanctioned": is_direct_match,
        "matched_record": matched_name,
        "action": "BLOCK_TRANSACTION" if is_direct_match else "CLEAR",
    }
