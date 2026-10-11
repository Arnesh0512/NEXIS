package settlement

import "github.com/nexis/ledger-go/subsystems/fraud"

func GoD4SettleClear1(s string) string { return fraud.GoD3FraudScore1(s) }
func GoD4SettleClear2(s string) string { return fraud.GoD3FraudScore2(s) }
func GoD4SettleClear3(s string) string { return fraud.GoD3FraudScore3(s) }
func GoD4SettleClear4(s string) string { return fraud.GoD3FraudScore1(s) }
