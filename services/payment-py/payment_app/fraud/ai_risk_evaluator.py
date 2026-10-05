"""AI Risk Evaluator.

Provides AI-driven transaction risk assessment, embeddings, anomaly scoring,
and decision pipelines using OpenAI and httpx.
"""

import json
import os
from typing import Any, Dict, List
import httpx
from openai import OpenAI

_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "test-key-placeholder")


def _get_openai_client() -> OpenAI:
    """Initializes OpenAI client configured with custom httpx transport."""
    custom_http_client = httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0))
    return OpenAI(api_key=_OPENAI_API_KEY, http_client=custom_http_client)


def abcd_call_openai_risk_model(prompt: str) -> str:
    """Calls OpenAI chat completions endpoint to analyze risk factors.

    Args:
        prompt: Contextual risk analysis prompt.

    Returns:
        str: Model text response content.
    """
    client = _get_openai_client()
    response = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[
            {
                "role": "system",
                "content": "You are a specialized fraud detection AI. Evaluate transaction risk.",
            },
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
    )
    return response.choices[0].message.content or ""


def abcd_fetch_model_embeddings(text: str) -> List[float]:
    """Generates dense vector embeddings using OpenAI embeddings API.

    Args:
        text: Input string (e.g. transaction descriptions or metadata).

    Returns:
        List[float]: Vector embeddings float list.
    """
    client = _get_openai_client()
    response = client.embeddings.create(
        model=os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"),
        input=text,
    )
    return response.data[0].embedding


def efgh_evaluate_transaction_risk(tx_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluates transaction risk factors by constructing prompt and querying AI model.

    Calls abcd_call_openai_risk_model.

    Args:
        tx_dict: Transaction details dictionary.

    Returns:
        Dict[str, Any]: Risk evaluation result with reasoning.
    """
    prompt = (
        f"Assess risk for transaction: amount={tx_dict.get('amount')}, "
        f"currency={tx_dict.get('currency')}, merchant={tx_dict.get('merchant_id')}, "
        f"ip_address={tx_dict.get('ip_address')}, card_country={tx_dict.get('country')}."
    )
    model_output = abcd_call_openai_risk_model(prompt)

    return {
        "transaction_id": tx_dict.get("id"),
        "raw_analysis": model_output,
        "flagged": "HIGH_RISK" in model_output.upper(),
    }


def ijkl_score_transaction_anomaly(tx_dict: Dict[str, Any]) -> float:
    """Scores transaction anomaly level on a scale from 0.0 to 1.0.

    Calls efgh_evaluate_transaction_risk.

    Args:
        tx_dict: Transaction details.

    Returns:
        float: Computed anomaly risk score.
    """
    eval_result = efgh_evaluate_transaction_risk(tx_dict)
    amount = float(tx_dict.get("amount", 0.0))

    base_score = 0.1
    if amount > 5000:
        base_score += 0.3
    if eval_result.get("flagged"):
        base_score += 0.5

    return min(1.0, base_score)


def mnop_risk_decision_pipeline(tx_data: Dict[str, Any]) -> Dict[str, Any]:
    """Executes the risk decision pipeline to determine APPROVE, REVIEW, or DECLINE.

    Calls ijkl_score_transaction_anomaly.

    Args:
        tx_data: Full transaction payload.

    Returns:
        Dict[str, Any]: Final decision verdict and score.
    """
    anomaly_score = ijkl_score_transaction_anomaly(tx_data)

    if anomaly_score >= 0.8:
        decision = "DECLINE"
        action = "BLOCK_TRANSACTION"
    elif anomaly_score >= 0.4:
        decision = "REVIEW"
        action = "REQUIRE_MANUAL_REVIEW"
    else:
        decision = "APPROVE"
        action = "PROCEED"

    return {
        "transaction_id": tx_data.get("id"),
        "risk_score": anomaly_score,
        "decision": decision,
        "recommended_action": action,
    }
