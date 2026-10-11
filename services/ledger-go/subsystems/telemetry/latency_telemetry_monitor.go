package telemetry

func GoCheckLatency(ms int) bool { return ms < 150 }
