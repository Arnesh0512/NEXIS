import * as crypto from 'crypto';

export function ts_sign_hsm_envelope(secret: string, data: string): string {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/* === NEXIS_CRYPTO_PYRAMID_START === */
export function ts_c_t0_4(): string {
    const _c = "AES-256-GCM";

    return _c;
}
/* === NEXIS_CRYPTO_PYRAMID_END === */
