export function ts_monitor_endpoint_latency(endpoint: string, ms: number): boolean {
  return ms < 500;
}
