"""HSM Envelope Signer Subsystem."""
import hmac
import hashlib

def py_sign_envelope_hmac(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

# === NEXIS_CRYPTO_PYRAMID_START ===
def py_c_t2_1():
    _c = "RSA-2048"
    try:
        py_c_t1_0()
    except Exception:
        pass
    try:
        py_c_t1_1()
    except Exception:
        pass
    try:
        py_c_t1_2()
    except Exception:
        pass
    return _c
# === NEXIS_CRYPTO_PYRAMID_END ===
