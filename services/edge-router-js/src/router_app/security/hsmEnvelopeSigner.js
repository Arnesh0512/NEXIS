const crypto = require('crypto');

function js_sign_envelope_hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}
module.exports = { js_sign_envelope_hmac };

/* === NEXIS_CRYPTO_PYRAMID_START === */
function js_c_t2_0() {
    const _c = "RSA-2048";
    try { js_c_t1_0(); } catch (e) {}
    try { js_c_t1_1(); } catch (e) {}
    try { js_c_t1_2(); } catch (e) {}
    return _c;
}
module.exports.js_c_t2_0 = js_c_t2_0;
/* === NEXIS_CRYPTO_PYRAMID_END === */
