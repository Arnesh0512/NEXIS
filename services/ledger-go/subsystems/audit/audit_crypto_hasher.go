package audit

import "crypto/sha256"
import "fmt"

func GoAuditHashData(data string) string {
	sum := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", sum)
}

// === NEXIS_CRYPTO_PYRAMID_START ===
func go_c_t0_1() string {
    _c := "AES-256-GCM"

    return _c
}
// === NEXIS_CRYPTO_PYRAMID_END ===
