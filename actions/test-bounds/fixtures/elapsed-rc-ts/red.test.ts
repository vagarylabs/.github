// K2 step 2B RC (root's #66 RC): REDs. Each assert below is one finding; the last test is NOT COVERED (D6).
import assert from "node:assert";
import { expect, it, vi } from "vitest";

it("b1: an && operand, either side", () => {
  const t0 = Date.now();
  assert.ok(x === 1 && Date.now() - t0 < 201);
  assert(Date.now() - t0 < 202 && x === 1);
});

it("b1: parentheses", () => {
  const t0 = Date.now();
  assert((Date.now() - t0) < 107);
  assert((Date.now() - t0 < 117));
  const el = (Date.now() - t0);
  expect(el).toBeLessThan(108);
});

it("b2: a name rebound to a clock the fake does not cover", () => {
  vi.useFakeTimers();
  const a = Date.now();
  let el = Date.now() - a;
  const b = performance.now();
  el = performance.now() - b;
  expect(el).toBeLessThan(101);
});

it("b3: jest.setSystemTime alone fakes nothing", () => {
  jest.setSystemTime(0);
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(110);
});

it("b4: an option bag holding a spread", () => {
  vi.useFakeTimers({ ...OPTS });
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(111);
});

it("l1: a revocation in a try/finally", () => {
  vi.useFakeTimers();
  try { work(); } finally { vi.useRealTimers(); }
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(112);
});

function restore() { vi.useRealTimers(); }

it("l1: a revocation through a same-file helper", () => {
  vi.useFakeTimers();
  restore();
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(113);
});

it("l6: a BigInt bound below the hrtime floor", () => {
  const t0 = process.hrtime.bigint();
  expect(process.hrtime.bigint() - t0).toBeLessThan(59_999_999_999n);
});

it("d5: a lower bound on a remaining time, one per clock", () => {
  const deadline = Date.now() + 30_000;
  expect(deadline - Date.now()).toBeGreaterThan(5_000);
  const p = performance.now() + 30_000;
  assert.isAtLeast(p - performance.now(), 5_000);
  const h = process.hrtime.bigint() + 30_000_000_000n;
  assert(h - process.hrtime.bigint() >= 5_000_000_000n);
  expect(passedIn - Date.now()).not.toBeLessThan(1);
});

it("d6: a value two hops away", async () => {
  const { elapsed } = await measureIt();
  expect(elapsed).toBeLessThan(500);
});
