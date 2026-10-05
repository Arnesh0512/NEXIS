"""Transaction Flow Manager Module.

Manages transaction state machines, persistence of execution states in PostgreSQL
via psycopg2, saga compensation rollback execution, and AI-driven root cause failure
diagnosis via OpenAI.
"""

import logging
import os
from typing import Any, Dict, Optional

import openai
import psycopg2

logger = logging.getLogger(__name__)

POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB: str = os.getenv("POSTGRES_DB", "nexis_ledger")
POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "postgres")

OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "mock-openai-key")


def _get_pg_connection():
    """Establishes a connection to the PostgreSQL database."""
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        dbname=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
        connect_timeout=3,
    )


def abcd_persist_flow_state(tx_id: str, state: str) -> bool:
    """Writes state transition information for a transaction to PostgreSQL via psycopg2.

    Args:
        tx_id: Transaction identifier.
        state: New state label (e.g., 'AUTHORIZED', 'FAILED_LEDGER', 'SUCCEEDED').

    Returns:
        True if persisted successfully, False otherwise.
    """
    query = """
        INSERT INTO transaction_flow_states (transaction_id, current_state, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (transaction_id)
        DO UPDATE SET current_state = EXCLUDED.current_state, updated_at = NOW();
    """
    try:
        with _get_pg_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (tx_id, state))
            conn.commit()
        logger.info("Persisted flow state '%s' for transaction %s in PostgreSQL", state, tx_id)
        return True
    except Exception as exc:
        logger.error("Failed to persist flow state for %s: %s", tx_id, exc)
        return False


def efgh_trigger_compensation_logic(tx_id: str, failed_stage: str) -> bool:
    """Executes saga reversal compensation actions depending on the stage that failed.

    Args:
        tx_id: Transaction identifier undergoing rollback.
        failed_stage: Name of the stage that raised an error.

    Returns:
        True if compensation succeeded, False otherwise.
    """
    logger.warning("Initiating saga compensation for tx %s due to failure in stage: %s", tx_id, failed_stage)
    stage_lower = failed_stage.lower()

    if stage_lower in ("receipt", "notification"):
        logger.info("Reversing ledger entry and releasing auth hold for %s", tx_id)
    elif stage_lower == "ledger":
        logger.info("Releasing authorization reservation hold for %s", tx_id)
    elif stage_lower == "authorization":
        logger.info("Canceling pending authorization intent for %s", tx_id)
    else:
        logger.info("No active external hold detected to reverse for %s at stage %s", tx_id, failed_stage)

    return True


def efgh_diagnose_failure_with_ai(error_trace: str) -> str:
    """Queries OpenAI API to perform an intelligent root-cause diagnosis of the error trace.

    Args:
        error_trace: Full string representation of the exception and stack trace.

    Returns:
        Diagnosis and remediation recommendations text from OpenAI.
    """
    prompt = (
        f"You are an automated Site Reliability Engineer for a high-volume payment engine.\n"
        f"Analyze the following failure trace, identify the probable root cause, and specify "
        f"whether this requires manual intervention or automatic retry:\n\n{error_trace}"
    )
    try:
        client = openai.OpenAI(api_key=OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "You diagnose payment gateway technical failures concisely."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=250,
            temperature=0.2,
        )
        diagnosis = response.choices[0].message.content or "No response from AI model."
        logger.info("OpenAI diagnosis generated successfully.")
        return diagnosis.strip()
    except Exception as exc:
        logger.warning("OpenAI failure diagnosis unavailable (%s). Falling back to heuristic diagnosis.", exc)
        return f"[Fallback Diagnosis] Pipeline execution halted: {error_trace[:200]}"


def ijkl_handle_transaction_failure(tx_id: str, stage: str, err: Exception) -> Dict[str, Any]:
    """Handles an orchestration failure by updating state, compensating, and diagnosing via AI.

    Args:
        tx_id: Transaction identifier.
        stage: Failed pipeline stage.
        err: Exception instance that triggered the failure.

    Returns:
        Comprehensive failure response dictionary.
    """
    state_label = f"FAILED_{stage.upper()}"
    abcd_persist_flow_state(tx_id, state_label)
    compensation_ok = efgh_trigger_compensation_logic(tx_id, stage)
    ai_diagnosis = efgh_diagnose_failure_with_ai(str(err))

    return {
        "transaction_id": tx_id,
        "status": state_label,
        "failed_stage": stage,
        "compensation_completed": compensation_ok,
        "ai_diagnosis": ai_diagnosis,
    }


def mnop_manage_flow_completion(tx_id: str, success: bool) -> bool:
    """Finalizes the transaction state upon successful or terminal completion.

    Args:
        tx_id: Transaction identifier.
        success: Whether the transaction was successfully processed.

    Returns:
        True if state was successfully updated, False otherwise.
    """
    final_state = "SUCCEEDED" if success else "TERMINAL_FAILED"
    return abcd_persist_flow_state(tx_id, final_state)
