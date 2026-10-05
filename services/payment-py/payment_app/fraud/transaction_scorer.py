"""Transaction Scorer.

Calculates merchant velocity risk, aggregates historical transactions from MongoDB,
and computes composite fraud scores with OpenAI explanations.
"""

import os
import time
from typing import Any, Dict, List
from openai import OpenAI
import pymongo


def abcd_query_merchant_velocity(merchant_id: str, window_seconds: int = 3600) -> List[Dict[str, Any]]:
    """Aggregates recent orders for a merchant from MongoDB.

    Args:
        merchant_id: Unique merchant identifier.
        window_seconds: Time window in seconds to query (default 1 hour).

    Returns:
        List[Dict[str, Any]]: List of recent transaction order records.
    """
    mongo_uri = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    db_name = os.getenv("MONGO_DB", "nexis_events")
    client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=5000)
    collection = client[db_name]["merchant_orders"]

    threshold_time = time.time() - window_seconds
    cursor = collection.find(
        {"merchant_id": merchant_id, "timestamp": {"$gte": threshold_time}}
    ).sort("timestamp", pymongo.DESCENDING)

    orders = []
    for doc in cursor:
        doc["_id"] = str(doc["_id"])
        orders.append(doc)
    return orders


def efgh_calculate_velocity_score(orders_list: List[Dict[str, Any]]) -> float:
    """Calculates velocity anomaly score based on frequency and aggregate amount.

    Args:
        orders_list: List of historical order records.

    Returns:
        float: Velocity risk score from 0.0 (normal) to 1.0 (severe velocity surge).
    """
    count = len(orders_list)
    if count == 0:
        return 0.0

    total_amount = sum(float(order.get("amount", 0.0)) for order in orders_list)

    # Heuristic: >50 transactions/hour or >$50,000 indicates surge
    freq_ratio = min(1.0, count / 50.0)
    vol_ratio = min(1.0, total_amount / 50000.0)

    velocity_score = (freq_ratio * 0.6) + (vol_ratio * 0.4)
    return round(velocity_score, 4)


def efgh_query_ai_fraud_explanation(score_data: Dict[str, Any]) -> str:
    """Queries OpenAI model to produce explainable reasoning for calculated scores.

    Args:
        score_data: Statistical and contextual scoring data.

    Returns:
        str: Human-readable AI fraud explanation.
    """
    api_key = os.getenv("OPENAI_API_KEY", "test-key-placeholder")
    client = OpenAI(api_key=api_key)

    prompt = (
        f"Explain fraud risk for merchant velocity: "
        f"order_count={score_data.get('order_count')}, "
        f"velocity_score={score_data.get('velocity_score')}, "
        f"current_tx_amount={score_data.get('current_tx_amount')}."
    )

    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {
                "role": "system",
                "content": "You are a merchant risk analyst explaining velocity fraud alerts.",
            },
            {"role": "user", "content": prompt},
        ],
        max_tokens=150,
    )
    return response.choices[0].message.content or "No explanation generated."


def ijkl_compute_composite_score(
    merchant_id: str, tx: Dict[str, Any]
) -> Dict[str, Any]:
    """Computes composite score combining velocity analysis and AI explanation.

    Calls abcd_query_merchant_velocity, efgh_calculate_velocity_score, and efgh_query_ai_fraud_explanation.

    Args:
        merchant_id: Target merchant identifier.
        tx: Current transaction details.

    Returns:
        Dict[str, Any]: Composite scoring results and explanation.
    """
    recent_orders = abcd_query_merchant_velocity(merchant_id)
    vel_score = efgh_calculate_velocity_score(recent_orders)

    score_payload = {
        "merchant_id": merchant_id,
        "order_count": len(recent_orders),
        "velocity_score": vel_score,
        "current_tx_amount": tx.get("amount", 0.0),
    }

    ai_explanation = efgh_query_ai_fraud_explanation(score_payload)

    composite_score = round((vel_score * 0.7) + (0.3 if float(tx.get("amount", 0.0)) > 10000 else 0.1), 4)

    return {
        "merchant_id": merchant_id,
        "transaction_id": tx.get("id"),
        "velocity_score": vel_score,
        "composite_score": min(1.0, composite_score),
        "ai_explanation": ai_explanation,
    }


def mnop_evaluate_merchant_fraud(
    merchant_id: str, tx: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluates merchant fraud risk and issues a final fraud flag.

    Calls ijkl_compute_composite_score.

    Args:
        merchant_id: Merchant identifier.
        tx: Transaction dictionary.

    Returns:
        Dict[str, Any]: Final merchant fraud evaluation verdict.
    """
    scoring = ijkl_compute_composite_score(merchant_id, tx)
    is_fraud_flagged = scoring["composite_score"] >= 0.75

    return {
        "merchant_id": merchant_id,
        "composite_score": scoring["composite_score"],
        "flagged": is_fraud_flagged,
        "reason": scoring["ai_explanation"],
        "action": "SUSPEND_SETTLEMENT" if is_fraud_flagged else "PASS",
    }
