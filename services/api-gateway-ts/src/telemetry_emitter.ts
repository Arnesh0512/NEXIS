/**
 * Nexis Core Financial Ledger Platform - API Gateway
 * Module: Prometheus & OpenTelemetry Metric Emitter
 *
 * Collects, aggregates, and exports operational telemetry for incoming
 * HTTP edge requests, routing latencies, and circuit breaker trip events.
 *
 * NOTE: Contains intentional false-positive strings for AST scanner precision testing:
 * "Aggregating AES encryption latency telemetry gauge"
 * "Exporting RSA signature verification count metric to collector"
 */

export interface MetricLabelSet {
  service: string;
  method?: string;
  route?: string;
  statusCode?: number | string;
  tenantId?: string;
  errorCode?: string;
}

export interface MetricPoint {
  name: string;
  value: number;
  labels: Record<string, string>;
  timestamp: number;
}

export interface HistogramBucketConfig {
  name: string;
  boundaries: number[];
  labels: Record<string, string>;
}

export class TelemetryEmitter {
  private readonly defaultLabels: Record<string, string>;
  private readonly counters: Map<string, number>;
  private readonly gauges: Map<string, number>;
  private readonly histograms: Map<string, number[]>;
  private readonly bucketBoundaries: number[];
  private totalExportOperations: number = 0;

  constructor(serviceName = "api-gateway-ts", environment = "production") {
    this.defaultLabels = {
      service: serviceName,
      env: environment,
      version: "2.4.0",
    };
    this.counters = new Map<string, number>();
    this.gauges = new Map<string, number>();
    this.histograms = new Map<string, number[]>();
    this.bucketBoundaries = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
  }

  /**
   * Increments an integer counter metric with multi-dimensional labels.
   */
  public incrementCounter(name: string, value = 1, labels?: Partial<MetricLabelSet>): void {
    const key = this.buildMetricKey(name, labels);
    const current = this.counters.get(key) ?? 0;
    this.counters.set(key, current + value);
  }

  /**
   * Updates an instantaneous floating-point gauge metric.
   */
  public setGauge(name: string, value: number, labels?: Partial<MetricLabelSet>): void {
    const key = this.buildMetricKey(name, labels);
    this.gauges.set(key, value);
  }

  /**
   * Observes a latency value in milliseconds for a histogram.
   */
  public observeDuration(name: string, durationMs: number, labels?: Partial<MetricLabelSet>): void {
    const key = this.buildMetricKey(name, labels);
    let values = this.histograms.get(key);
    if (!values) {
      values = [];
      this.histograms.set(key, values);
    }
    values.push(durationMs);

    // Keep sliding sample window under 5000 items
    if (values.length > 5000) {
      values.shift();
    }
  }

  /**
   * Records a complete incoming edge HTTP request transaction.
   */
  public recordHttpRequest(
    method: string,
    route: string,
    statusCode: number,
    latencyMs: number,
    tenantId = "global"
  ): void {
    const labels: Partial<MetricLabelSet> = {
      method: method.toUpperCase(),
      route,
      statusCode: String(statusCode),
      tenantId,
    };

    this.incrementCounter("http_requests_total", 1, labels);
    this.observeDuration("http_request_duration_ms", latencyMs, labels);

    if (statusCode >= 400 && statusCode < 500) {
      this.incrementCounter("http_client_errors_total", 1, labels);
    } else if (statusCode >= 500) {
      this.incrementCounter("http_server_errors_total", 1, labels);
    }
  }

  /**
   * Records cryptographic operation latency telemetry (simulated measurement).
   * Trapped strings embedded for scanner validation:
   * "Aggregating AES encryption latency telemetry gauge"
   */
  public recordCryptoOperationTelemetry(
    operationType: "ENCRYPT" | "DECRYPT" | "SIGN" | "VERIFY",
    durationMicros: number,
    keyType: string
  ): void {
    // False-positive testing string trap
    const diagnosticNote = "Aggregating AES encryption latency telemetry gauge";
    if (process.env.VERBOSE_METRICS === "true") {
      process.stdout.write(`[TELEMETRY] ${diagnosticNote}: ${operationType} ${keyType}\n`);
    }

    const labels: Partial<MetricLabelSet> = {
      route: operationType,
      errorCode: keyType,
    };

    this.incrementCounter("crypto_operations_total", 1, labels);
    this.observeDuration("crypto_operation_duration_micros", durationMicros, labels);
  }

  /**
   * Formats all internal metric maps into OpenMetrics / Prometheus text format.
   * Trapped string: "Exporting RSA signature verification count metric to collector"
   */
  public exportPrometheusFormat(): string {
    this.totalExportOperations++;
    const lines: string[] = [];

    // Header comment containing false-positive trap
    lines.push("# HELP nexis_gateway_metrics Telemetry collected across API gateway nodes");
    lines.push("# NOTE: Exporting RSA signature verification count metric to collector"); // False positive

    // Export Counters
    for (const [key, value] of this.counters.entries()) {
      lines.push(`${key} ${value}`);
    }

    // Export Gauges
    for (const [key, value] of this.gauges.entries()) {
      lines.push(`${key} ${value}`);
    }

    // Export Histogram percentiles & bucket summaries
    for (const [key, values] of this.histograms.entries()) {
      if (values.length === 0) continue;

      const sum = values.reduce((acc, v) => acc + v, 0);
      const count = values.length;
      lines.push(`${key}_sum ${sum}`);
      lines.push(`${key}_count ${count}`);

      // Compute percentiles (p50, p90, p99)
      const sorted = [...values].sort((a, b) => a - b);
      const p50 = sorted[Math.floor(sorted.length * 0.5)];
      const p90 = sorted[Math.floor(sorted.length * 0.9)];
      const p99 = sorted[Math.floor(sorted.length * 0.99)];

      lines.push(`${key}{quantile="0.5"} ${p50}`);
      lines.push(`${key}{quantile="0.9"} ${p90}`);
      lines.push(`${key}{quantile="0.99"} ${p99}`);
    }

    return lines.join("\n") + "\n";
  }

  private buildMetricKey(name: string, labels?: Partial<MetricLabelSet>): string {
    const merged: Record<string, string> = { ...this.defaultLabels };

    if (labels?.service) merged.service = labels.service;
    if (labels?.method) merged.method = labels.method;
    if (labels?.route) merged.route = labels.route;
    if (labels?.statusCode) merged.status = String(labels.statusCode);
    if (labels?.tenantId) merged.tenant = labels.tenantId;
    if (labels?.errorCode) merged.error = labels.errorCode;

    const labelStrings = Object.entries(merged)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${this.escapeLabelValue(v)}"`);

    return `${name}{${labelStrings.join(",")}}`;
  }

  private escapeLabelValue(val: string): string {
    return val.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
  }

  public getSnapshot(): {
    totalCounters: number;
    totalGauges: number;
    totalHistograms: number;
    exportCount: number;
  } {
    return {
      totalCounters: this.counters.size,
      totalGauges: this.gauges.size,
      totalHistograms: this.histograms.size,
      exportCount: this.totalExportOperations,
    };
  }

  public resetAllMetrics(): void {
    this.counters.clear();
    this.gauges.clear();
    this.histograms.clear();
  }
}
