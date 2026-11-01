// Planted REDs in javascript: one per clock family.
const { expect, it } = require("vitest");

it("is fast", () => {
  const started = Date.now();
  const elapsed = Date.now() - started;
  expect(elapsed).toBeLessThan(1000);
  expect(performance.now() - started < 500).toBe(true);
  expect(process.hrtime.bigint() - h0).toBeLessThan(5_000_000n);
});

it("is a lower bound on a remaining time (D5), one per clock family", () => {
  const d = Date.now() + 30_000;
  expect(d - Date.now()).toBeGreaterThan(5_000);
  const p = performance.now() + 30_000;
  expect(p - performance.now()).toBeGreaterThan(5_000);
  const h = process.hrtime.bigint() + 30_000_000_000n;
  expect(h - process.hrtime.bigint()).toBeGreaterThan(5_000_000_000n);
});
