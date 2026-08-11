import * as crypto from 'crypto';

const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const HISTOGRAM_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10];

function assertMetricName(name) {
  if (typeof name !== 'string' || !METRIC_NAME.test(name)) {
    throw new Error('invalid metric name');
  }
}

function cloneHistogram(value) {
  return {
    count: value.count,
    sum: value.sum,
    buckets: [...value.buckets],
  };
}

/**
 * Small dependency-free metrics registry. Metric names are fixed at call sites
 * and never include request data, identifiers, or other attacker-controlled
 * values, which keeps the registry bounded and privacy-safe.
 */
export function createMetrics() {
  const counters = new Map();
  const gauges = new Map();
  const histograms = new Map();

  function increment(name, amount = 1) {
    assertMetricName(name);
    if (!Number.isSafeInteger(amount) || amount < 0) throw new Error('metric increment must be a non-negative integer');
    counters.set(name, (counters.get(name) || 0) + amount);
  }

  function setGauge(name, value) {
    assertMetricName(name);
    if (!Number.isFinite(value)) throw new Error('metric gauge must be finite');
    gauges.set(name, value);
  }

  function observe(name, value) {
    assertMetricName(name);
    if (!Number.isFinite(value) || value < 0) throw new Error('metric observation must be a non-negative finite number');
    let histogram = histograms.get(name);
    if (!histogram) {
      histogram = { count: 0, sum: 0, buckets: Array(HISTOGRAM_BUCKETS.length).fill(0) };
      histograms.set(name, histogram);
    }
    histogram.count += 1;
    histogram.sum += value;
    HISTOGRAM_BUCKETS.forEach((bucket, index) => {
      if (value <= bucket) histogram.buckets[index] += 1;
    });
  }

  function snapshot() {
    return {
      counters: Object.fromEntries(counters),
      gauges: Object.fromEntries(gauges),
      histograms: Object.fromEntries([...histograms].map(([name, value]) => [name, cloneHistogram(value)])),
    };
  }

  function toPrometheus() {
    const lines = [];
    for (const [name, value] of counters) {
      lines.push(`# TYPE ${name} counter`, `${name} ${value}`);
    }
    for (const [name, value] of gauges) {
      lines.push(`# TYPE ${name} gauge`, `${name} ${value}`);
    }
    for (const [name, value] of histograms) {
      lines.push(`# TYPE ${name} histogram`);
      HISTOGRAM_BUCKETS.forEach((bucket, index) => {
        lines.push(`${name}_bucket{le="${bucket}"} ${value.buckets[index]}`);
      });
      lines.push(`${name}_bucket{le="+Inf"} ${value.count}`);
      lines.push(`${name}_sum ${value.sum}`);
      lines.push(`${name}_count ${value.count}`);
    }
    return `${lines.join('\n')}\n`;
  }

  function authorizeToken(candidate, expected) {
    if (!expected) return true;
    const left = Buffer.from(candidate || '', 'utf8');
    const right = Buffer.isBuffer(expected) ? Buffer.from(expected.toString('base64'), 'utf8') : Buffer.from(expected, 'utf8');
    return left.length === right.length && crypto.timingSafeEqual(left, right);
  }

  return Object.freeze({ increment, setGauge, observe, snapshot, toPrometheus, authorizeToken });
}

export { HISTOGRAM_BUCKETS };
