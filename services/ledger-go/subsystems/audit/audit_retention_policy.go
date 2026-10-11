package audit

func GoAuditRetentionValid(days int) bool { return days >= 365 }
