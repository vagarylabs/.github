// Planted REDs in tsx: one per clock family, and the comparison form beside JSX.
import { expect, it } from "vitest";

it("renders fast", () => {
  const t0 = Date.now();
  render(<Panel />);
  expect(Date.now() - t0).toBeLessThan(1_000);
  assert(performance.now() - t0 < 800);
  expect(process.hrtime.bigint() - h0).toBeLessThan(BUDGET_NS);
});

it("is a lower bound on a remaining time (D5), one per clock family", () => {
  const d = Date.now() + 30_000;
  expect(d - Date.now()).toBeGreaterThan(5_000);
  const p = performance.now() + 30_000;
  expect(p - performance.now()).toBeGreaterThan(5_000);
  const h = process.hrtime.bigint() + 30_000_000_000n;
  expect(h - process.hrtime.bigint()).toBeGreaterThan(5_000_000_000n);
});
