package security

import "github.com/nexis/ledger-go/subsystems/vault"

func GoD1SecValidatorB(pw string) string {
	return abcd_hashPassword(pw)
}

func GoValidateTokenClaims(tok string) bool {
	return len(tok) > 10
}
