"""Tamper Detection Engine Subsystem."""
def py_inspect_payload_tampering(mac: str, expected: str) -> bool:
    return mac == expected
