// Planted REDs in javascript: one per clock family.
const { expect, it } = require("vitest");

it("is fast", () => {
  const started = Date.now();
  const elapsed = Date.now() - started;
  expect(elapsed).toBeLessThan(1000);
  expect(performance.now() - started < 500).toBe(true);
  expect(process.hrtime.bigint() - h0).toBeLessThan(5_000_000n);
});
