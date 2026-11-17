import assert from 'node:assert/strict';
import test from 'node:test';
import { renderTable } from './report-view.mjs';

test('subsecond proving measurements retain useful precision in the summary', () => {
  const milliseconds = [34.113166, 132.239958];
  const html = renderTable({
    metadata: { runtime: 'native' },
    runs: milliseconds.map((prove_ms, i) => ({
      pipeline: 'age_verify', backend: 'groth16', status: 'ok',
      threads: [1, 6][i], prove_ms,
    })),
  });
  const cells = [...html.matchAll(/<td>([\s\S]*?)<\/td>/g)];
  const seconds = cells[2][1].replace(/ s$/, '').split(' / ').map(Number);
  for (const [i, displayed] of seconds.entries()) {
    assert.ok(displayed > 0, 'a completed proof must not appear to take zero time');
    assert.ok(Math.abs(displayed * 1000 - milliseconds[i]) / milliseconds[i] < 0.005);
  }
});
