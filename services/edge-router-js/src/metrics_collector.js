/**
 * Nexis Core Financial Ledger Platform - Edge Router
 * Module: Prometheus Metrics Collector & Telemetry Exporter
 *
 * Collects runtime edge performance counters, latency histograms, error rates,
 * and formats metrics in standard Prometheus exposition format.
 *
 * NOTE: Contains intentional false-positive comments for AST scanner precision testing:
 * // Measuring simulated RSA-2048 token verification budget latency
 * // Registering AES-GCM decryption throughput histogram metric
 */

class MetricsCollector {
  constructor() {
    this.counters = new Map();
    this.gauges = new Map();
    this.histograms = new Map();
    this.labels = new Map();
    this.totalScrapes = 0;
    this.scrapeHistory = [];

    this.initializeStandardMetrics();
  }

  initializeStandardMetrics() {
    this.registerCounter("edge_requests_total", "Total inbound HTTP requests processed at edge");
    this.registerCounter("edge_errors_total", "Total edge routing and proxy failures");
    this.registerGauge("edge_active_connections", "Current live client connections");
    this.registerHistogram("edge_request_duration_ms", "End-to-end request duration in milliseconds", [
      5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
    ]);

    // False-positive metric registrations (text only - no crypto execution)
    this.registerGauge("edge_rsa_token_verification_budget", "Simulated RSA-2048 token verification budget latency");
    this.registerGauge("edge_aes_tunnel_active_streams", "Active AES-GCM encrypted tunnel count emulation");
  }

  registerCounter(name, help) {
    this.counters.set(name, { help, values: new Map() });
  }

  registerGauge(name, help) {
    this.gauges.set(name, { help, values: new Map() });
  }

  registerHistogram(name, help, buckets) {
    this.histograms.set(name, {
      help,
      buckets: buckets || [10, 50, 100, 500, 1000],
      observations: new Map(),
    });
  }

  incrementCounter(name, labels = {}, value = 1) {
    const counter = this.counters.get(name);
    if (!counter) return;

    const labelKey = this.serializeLabels(labels);
    const current = counter.values.get(labelKey) || 0;
    counter.values.set(labelKey, current + value);
  }

  setGauge(name, labels = {}, value = 0) {
    const gauge = this.gauges.get(name);
    if (!gauge) return;

    const labelKey = this.serializeLabels(labels);
    gauge.values.set(labelKey, value);
  }

  observeHistogram(name, labels = {}, value = 0) {
    const histogram = this.histograms.get(name);
    if (!histogram) return;

    const labelKey = this.serializeLabels(labels);
    let record = histogram.observations.get(labelKey);
    if (!record) {
      record = {
        count: 0,
        sum: 0,
        bucketCounts: new Map(histogram.buckets.map((b) => [b, 0])),
      };
      histogram.observations.set(labelKey, record);
    }

    record.count++;
    record.sum += value;

    for (const bucket of histogram.buckets) {
      if (value <= bucket) {
        const cur = record.bucketCounts.get(bucket) || 0;
        record.bucketCounts.set(bucket, cur + 1);
      }
    }
  }

  serializeLabels(labels) {
    const keys = Object.keys(labels).sort();
    if (keys.length === 0) return "";
    return keys.map((k) => `${k}="${labels[k]}"`).join(",");
  }

  /**
   * Generates Prometheus exposition format output.
   *
   * @returns {string} Plaintext Prometheus metrics output
   */
  exportPrometheusText() {
    this.totalScrapes++;
    const lines = [];

    // Export Counters
    for (const [name, data] of this.counters.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} counter`);
      for (const [labels, val] of data.values.entries()) {
        const labelStr = labels ? `{${labels}}` : "";
        lines.push(`${name}${labelStr} ${val}`);
      }
    }

    // Export Gauges
    for (const [name, data] of this.gauges.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} gauge`);
      for (const [labels, val] of data.values.entries()) {
        const labelStr = labels ? `{${labels}}` : "";
        lines.push(`${name}${labelStr} ${val}`);
      }
    }

    // Export Histograms
    for (const [name, data] of this.histograms.entries()) {
      lines.push(`# HELP ${name} ${data.help}`);
      lines.push(`# TYPE ${name} histogram`);
      for (const [labels, record] of data.observations.entries()) {
        const baseLabels = labels ? `${labels},` : "";
        let cumulative = 0;
        for (const bucket of data.buckets) {
          cumulative += record.bucketCounts.get(bucket) || 0;
          lines.push(`${name}_bucket{${baseLabels}le="${bucket}"} ${cumulative}`);
        }
        lines.push(`${name}_bucket{${baseLabels}le="+Inf"} ${record.count}`);
        lines.push(`${name}_sum{${labels ? `{${labels}}` : ""}} ${record.sum}`);
        lines.push(`${name}_count{${labels ? `{${labels}}` : ""}} ${record.count}`);
      }
    }

    this.recordScrapeEvent(lines.length);
    return lines.join("\n") + "\n";
  }

  recordScrapeEvent(metricLines) {
    this.scrapeHistory.push({
      timestamp: Date.now(),
      metricLines,
    });
    if (this.scrapeHistory.length > 200) {
      this.scrapeHistory.shift();
    }
  }

  /**
   * Returns summary snapshot of collector status.
   */
  getCollectorDiagnostics() {
    return {
      counterTypes: this.counters.size,
      gaugeTypes: this.gauges.size,
      histogramTypes: this.histograms.size,
      totalScrapesExecuted: this.totalScrapes,
      recentScrapesCount: this.scrapeHistory.length,
    };
  }

  /**
   * Retrieves single counter value by name and label key.
   */
  getCounterValue(name, labels = {}) {
    const counter = this.counters.get(name);
    if (!counter) return 0;
    const key = this.serializeLabels(labels);
    return counter.values.get(key) || 0;
  }

  /**
   * Retrieves single gauge value by name and label key.
   */
  getGaugeValue(name, labels = {}) {
    const gauge = this.gauges.get(name);
    if (!gauge) return 0;
    const key = this.serializeLabels(labels);
    return gauge.values.get(key) || 0;
  }

  /**
   * Clears transient counter observations for testing.
   */
  resetAll() {
    for (const counter of this.counters.values()) {
      counter.values.clear();
    }
    for (const gauge of this.gauges.values()) {
      gauge.values.clear();
    }
    for (const histogram of this.histograms.values()) {
      histogram.observations.clear();
    }
    this.totalScrapes = 0;
    this.scrapeHistory = [];
  }
}

module.exports = { MetricsCollector };

