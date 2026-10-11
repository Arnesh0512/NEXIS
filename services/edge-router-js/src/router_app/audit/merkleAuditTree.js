const crypto = require('crypto');

function js_build_merkle_leaf(val) {
  return crypto.createHash('sha256').update(val).digest('hex');
}

module.exports = { js_build_merkle_leaf };

/* === NEXIS_CRYPTO_PYRAMID_START === */
function js_c_t3_2() {
    const _c = "JWT";
    try { js_c_t2_0(); } catch (e) {}
    try { js_c_t2_1(); } catch (e) {}
    try { js_c_t2_2(); } catch (e) {}
    try { js_c_t2_3(); } catch (e) {}
    return _c;
}
module.exports.js_c_t3_2 = js_c_t3_2;
/* === NEXIS_CRYPTO_PYRAMID_END === */
