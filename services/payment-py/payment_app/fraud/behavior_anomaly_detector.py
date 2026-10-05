"""Behavior Anomaly Detector.

Analyzes user behavioral patterns, impossible speed/location jumps, and leverages
OpenAI and MongoDB to enforce adaptive step-up authentication.
"""

import math
import os
import time
from typing import Any, Dict, List, Optional
from openai import OpenAI
import pymongo


def abcd_fetch_user_history(user_id: str, limit: int = 20) -> List[Dict[str, Any]]:
    """Reads historical user activity and transaction logs from MongoDB.

    Args:
        user_id: Unique user identifier.
        limit: Max number of recent activity records to retrieve.

    Returns:
        List[Dict[str, Any]]: User historical events sorted by timestamp descending.
    """
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB", "nexis_events")
    client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    collection = client[db_name]["user_activity_logs"]

    cursor = (
        collection.find({"user_id": user_id})
        .sort("timestamp", pymongo.DESCENDING)
        .limit(limit)
    )

    history = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        history.append(doc)
    return history


def efgh_detect_location_jump(
    current_loc: Dict[str, Any], last_loc: Dict[str, Any]
) -> Dict[str, Any]:
    """Calculates geographical distance and travel velocity to detect impossible travel.

    Uses the Haversine formula on latitude/longitude and time delta.

    Args:
        current_loc: Current event location with 'lat', 'lon', and 'timestamp'.
        last_loc: Previous event location with 'lat', 'lon', and 'timestamp'.

    Returns:
        Dict[str, Any]: Calculated distance (km), velocity (km/h), and impossible jump flag.
    """
    lat1 = float(current_loc.get("lat", 0.0))
    lon1 = float(current_loc.get("lon", 0.0))
    t1 = float(current_loc.get("timestamp", time.time()))

    lat2 = float(last_loc.get("lat", 0.0))
    lon2 = float(last_loc.get("lon", 0.0))
    t2 = float(last_loc.get("timestamp", t1 - 3600))

    # Haversine distance calculation in kilometers
    radius_km = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    a = (
        math.sin(d_lat / 2.0) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(d_lon / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    distance_km = radius_km * c

    hours_diff = max(0.001, abs(t1 - t2) / 3600.0)
    speed_kmh = distance_km / hours_diff

    # Commercial air travel rarely exceeds 900 km/h
    is_impossible = speed_kmh > 900.0 and distance_km > 300.0

    return {
        "distance_km": round(distance_km, 2),
        "speed_kmh": round(speed_kmh, 2),
        "is_impossible_jump": is_impossible,
    }


def efgh_summarize_behavior_with_ai(history: List[Dict[str, Any]]) -> str:
    """Queries OpenAI to synthesize behavioral trends and flag deviations from baseline.

    Args:
        history: Chronological user activity logs.

    Returns:
        str: AI behavioral summary and risk assessment text.
    """
    api_key = os.getenv("OPENAI_API_KEY", "test-key-placeholder")
    client = OpenAI(api_key=api_key)

    sample_events = [
        {"action": e.get("action"), "loc": e.get("location"), "ts": e.get("timestamp")}
        for e in history[:5]
    ]

    prompt = (
        f"Review these recent user actions and identify if behavior deviates from baseline: "
        f"{sample_events}"
    )

    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {
                "role": "system",
                "content": "You are a cyber fraud analyst detecting account takeover patterns.",
            },
            {"role": "user", "content": prompt},
        ],
        max_tokens=150,
    )
    return response.choices[0].message.content or "Standard user activity profile."


def ijkl_evaluate_account_security(
    user_id: str, current_event: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluates full account security posture against historical baseline and physics checks.

    Calls abcd_fetch_user_history, efgh_detect_location_jump, and efgh_summarize_behavior_with_ai.

    Args:
        user_id: Target user ID.
        current_event: Incoming event payload (e.g. login or payment authorization).

    Returns:
        Dict[str, Any]: Risk score, jump detection stats, and AI behavior summary.
    """
    history = abcd_fetch_user_history(user_id)

    current_loc = current_event.get(
        "location", {"lat": 37.7749, "lon": -122.4194, "timestamp": time.time()}
    )
    last_loc = (
        history[0].get("location")
        if history and "location" in history[0]
        else {"lat": 37.7749, "lon": -122.4194, "timestamp": time.time() - 7200}
    )

    jump_analysis = efgh_detect_location_jump(current_loc, last_loc)
    ai_summary = efgh_summarize_behavior_with_ai(history)

    risk_score = 0.1
    if jump_analysis["is_impossible_jump"]:
        risk_score += 0.7

    return {
        "user_id": user_id,
        "risk_score": min(1.0, risk_score),
        "location_jump": jump_analysis,
        "ai_behavior_summary": ai_summary,
    }


def mnop_trigger_step_up_auth(user_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """Determines whether step-up multi-factor authentication is required.

    Calls ijkl_evaluate_account_security.

    Args:
        user_id: User identifier.
        event: Incoming transaction/login event.

    Returns:
        Dict[str, Any]: Step-up authentication decision and challenge parameters.
    """
    evaluation = ijkl_evaluate_account_security(user_id, event)
    is_step_up_required = (
        evaluation["risk_score"] >= 0.5
        or evaluation["location_jump"]["is_impossible_jump"]
    )

    return {
        "user_id": user_id,
        "step_up_required": is_step_up_required,
        "risk_score": evaluation["risk_score"],
        "challenge_type": "FIDO2_OR_TOTP" if is_step_up_required else "NONE",
        "reason": (
            "Impossible location jump or anomalous behavior detected"
            if is_step_up_required
            else "Risk within acceptable threshold"
        ),
    }
