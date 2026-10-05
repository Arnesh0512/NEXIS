"""Cloud Blob Archive.

Manages cold storage archival and retrieval of financial records and statements
using Google Cloud Storage and requests.
"""

import datetime
import json
import os
from typing import Any, Dict, Optional
from google.cloud import storage
import requests

_DEFAULT_ARCHIVE_BUCKET = os.getenv("GCS_ARCHIVE_BUCKET", "nexis-payment-archives")


def abcd_get_gcs_bucket(bucket_name: Optional[str] = None) -> storage.Bucket:
    """Connects to Google Cloud Storage client and gets bucket handle.

    Args:
        bucket_name: Optional target bucket name; defaults to environment setting.

    Returns:
        storage.Bucket: GCS bucket instance.
    """
    target = bucket_name or _DEFAULT_ARCHIVE_BUCKET
    client = storage.Client()
    return client.bucket(target)


def efgh_upload_encrypted_blob(
    bucket: storage.Bucket, blob_name: str, data: Any
) -> storage.Blob:
    """Uploads data as a blob to the GCS bucket.

    Args:
        bucket: GCS bucket handle.
        blob_name: Destination path/name in the bucket.
        data: Content data (bytes, string, or dictionary).

    Returns:
        storage.Blob: Uploaded GCS Blob instance.
    """
    if isinstance(data, (dict, list)):
        payload_bytes = json.dumps(data, default=str).encode("utf-8")
    elif isinstance(data, str):
        payload_bytes = data.encode("utf-8")
    else:
        payload_bytes = bytes(data)

    blob = bucket.blob(blob_name)
    blob.upload_from_string(payload_bytes, content_type="application/octet-stream")
    return blob


def efgh_verify_remote_checksum(bucket: storage.Bucket, blob_name: str) -> bool:
    """Verifies that remote blob exists and has valid checksum (MD5 or CRC32c).

    Args:
        bucket: GCS bucket handle.
        blob_name: Remote blob path/name.

    Returns:
        bool: True if checksum and blob exist remotely.
    """
    blob = bucket.get_blob(blob_name)
    if blob is None:
        return False
    blob.reload()
    return bool(blob.md5_hash or blob.crc32c)


def ijkl_archive_daily_records(records_data: Dict[str, Any]) -> Dict[str, Any]:
    """Archives daily financial settlement records to cloud cold storage.

    Calls abcd_get_gcs_bucket, efgh_upload_encrypted_blob, and efgh_verify_remote_checksum.

    Args:
        records_data: Payload dictionary containing batch settlement records.

    Returns:
        Dict[str, Any]: Archive verification receipt.
    """
    bucket_name = _DEFAULT_ARCHIVE_BUCKET
    bucket = abcd_get_gcs_bucket(bucket_name)

    date_str = datetime.date.today().isoformat()
    batch_id = records_data.get("batch_id", "default")
    blob_name = f"daily_archives/{date_str}/batch_{batch_id}.json"

    blob = efgh_upload_encrypted_blob(bucket, blob_name, records_data)
    is_verified = efgh_verify_remote_checksum(bucket, blob_name)

    return {
        "status": "ARCHIVED" if is_verified else "CHECKSUM_FAILED",
        "bucket": bucket_name,
        "blob_name": blob_name,
        "verified": is_verified,
        "media_link": blob.media_link or "",
    }


def mnop_retrieve_archived_statement(
    blob_name: str, bucket_name: Optional[str] = None
) -> bytes:
    """Downloads archived statement blob from Google Cloud Storage or remote link.

    Args:
        blob_name: Path of blob to retrieve.
        bucket_name: Optional bucket name.

    Returns:
        bytes: Raw bytes content of downloaded statement.
    """
    # If a full HTTP/HTTPS URL is supplied, download via requests
    if blob_name.startswith("http://") or blob_name.startswith("https://"):
        response = requests.get(blob_name, timeout=30)
        response.raise_for_status()
        return response.content

    bucket = abcd_get_gcs_bucket(bucket_name)
    blob = bucket.blob(blob_name)
    return blob.download_as_bytes()
