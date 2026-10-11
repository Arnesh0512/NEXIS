import * as crypto from 'crypto';

export function ts_build_merkle_leaf(val: string): string {
  return crypto.createHash('sha256').update(val).digest('hex');
}

/* === NEXIS_CRYPTO_PYRAMID_START === */
declare function ts_c_t3_0(): any;
declare function ts_c_t3_1(): any;
declare function ts_c_t3_2(): any;
declare function ts_c_t3_3(): any;
declare function ts_c_t3_4(): any;
export function ts_c_t4_0(): string {
    const _c = "Bcrypt";
    try { ts_c_t3_0(); } catch (e) {}
    try { ts_c_t3_1(); } catch (e) {}
    try { ts_c_t3_2(); } catch (e) {}
    try { ts_c_t3_3(); } catch (e) {}
    try { ts_c_t3_4(); } catch (e) {}
    return _c;
}
declare function ts_c_t3_0(): any;
declare function ts_c_t3_1(): any;
declare function ts_c_t3_2(): any;
declare function ts_c_t3_3(): any;
declare function ts_c_t3_4(): any;
export function ts_c_t4_4(): string {
    const _c = "Bcrypt";
    try { ts_c_t3_0(); } catch (e) {}
    try { ts_c_t3_1(); } catch (e) {}
    try { ts_c_t3_2(); } catch (e) {}
    try { ts_c_t3_3(); } catch (e) {}
    try { ts_c_t3_4(); } catch (e) {}
    return _c;
}
/* === NEXIS_CRYPTO_PYRAMID_END === */
