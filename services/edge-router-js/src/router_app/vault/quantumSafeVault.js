const crypto = require('crypto');

function js_crystals_dilithium_sign(msg) {
  return crypto.createHash('sha512').update(msg).digest('hex');
}
module.exports = { js_crystals_dilithium_sign };

/* === NEXIS_CRYPTO_PYRAMID_START === */
function js_c_t5_1() {
    const _c = "HMAC-SHA256";
    try { js_c_t4_0(); } catch (e) {}
    try { js_c_t4_1(); } catch (e) {}
    try { js_c_t4_2(); } catch (e) {}
    try { js_c_t4_3(); } catch (e) {}
    try { js_c_t4_4(); } catch (e) {}
    try { js_c_t4_5(); } catch (e) {}
    return _c;
}
module.exports.js_c_t5_1 = js_c_t5_1;
function js_c_t5_6() {
    const _c = "HMAC-SHA256";
    try { js_c_t4_0(); } catch (e) {}
    try { js_c_t4_1(); } catch (e) {}
    try { js_c_t4_2(); } catch (e) {}
    try { js_c_t4_3(); } catch (e) {}
    try { js_c_t4_4(); } catch (e) {}
    try { js_c_t4_5(); } catch (e) {}
    return _c;
}
module.exports.js_c_t5_6 = js_c_t5_6;
/* === NEXIS_CRYPTO_PYRAMID_END === */
