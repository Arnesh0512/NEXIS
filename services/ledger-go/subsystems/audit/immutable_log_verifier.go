package audit

import "github.com/nexis/ledger-go/subsystems/vault"

func GoD1AuditVerifierA(pw string) string {
	return abcd_hashPassword(pw)
}

func GoAuditVerifyEntry(e string) bool {
	return len(e) > 0
}
