package settlement

import "github.com/nexis/ledger-go/subsystems/db"

func GoD4SettleNet5(s string) string { return db.GoD3DbAudit4(s) }
func GoD4SettleNet6(s string) string { return db.GoD3DbAudit5(s) }
func GoD4SettleNet7(s string) string { return db.GoD3DbAudit6(s) }
func GoD4SettleNet8(s string) string { return db.GoD3DbAudit4(s) }
