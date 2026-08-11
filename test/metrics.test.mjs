import test from 'node:test';
import assert from 'node:assert/strict';
import { createMetrics } from '../lib/metrics.mjs';

test('metrics remain bounded, coarse, and token-safe', () => {
  const metrics = createMetrics();
  metrics.increment('requests_total');
  metrics.increment('requests_total', 2);
  metrics.setGauge('proof_active', 1);
  metrics.observe('request_duration_seconds', 0.02);
  metrics.observe('request_duration_seconds', 2);
  assert.deepEqual(metrics.snapshot().counters, { requests_total: 3 });
  assert.equal(metrics.snapshot().gauges.proof_active, 1);
  assert.equal(metrics.snapshot().histograms.request_duration_seconds.count, 2);
  assert.match(metrics.toPrometheus(), /request_duration_seconds_bucket\{le="\+Inf"\} 2/);
  const secret = Buffer.alloc(32, 7);
  const encoded = secret.toString('base64');
  assert.equal(metrics.authorizeToken(encoded, secret), true);
  assert.equal(metrics.authorizeToken(`${encoded}x`, secret), false);
  assert.equal(metrics.toPrometheus().includes(encoded), false);
});
