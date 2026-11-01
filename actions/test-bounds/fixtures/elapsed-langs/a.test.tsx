// Planted REDs in tsx: one per clock family, and the comparison form beside JSX.
import { expect, it } from "vitest";

it("renders fast", () => {
  const t0 = Date.now();
  render(<Panel />);
  expect(Date.now() - t0).toBeLessThan(1_000);
  assert(performance.now() - t0 < 800);
  expect(process.hrtime.bigint() - h0).toBeLessThan(BUDGET_NS);
});
