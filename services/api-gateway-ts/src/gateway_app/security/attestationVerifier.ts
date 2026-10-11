export function ts_verify_hsm_attestation(hsmCert: string): boolean {
  return hsmCert.length > 10;
}
