// K2 step 2B RC (root's #66 RC): GREENs. Five asserts clear; the rest are not elapsed asserts at all.
import assert from "node:assert";
import { expect, it, vi } from "vitest";

it("l5: a sinon clock declared with const", () => {
  const clock = sinon.useFakeTimers();
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(114);
});

it("l6: a BigInt bound at the hrtime floor", () => {
  const t0 = process.hrtime.bigint();
  expect(process.hrtime.bigint() - t0).toBeLessThan(60_000_000_000n);
});

it("d5: a budget that leaves the floor", () => {
  const d2 = Date.now() + 300_000;
  expect(d2 - Date.now()).toBeGreaterThanOrEqual(5_000);
});

it("vi.setSystemTime fakes Date with real timers", () => {
  vi.setSystemTime(0);
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(115);
});

it("not required true, or compliant", () => {
  const t0 = Date.now();
  assert(ok || Date.now() - t0 < 109);
  assert(!(Date.now() - t0 < 3));
  const deadline = Date.now() + 30_000;
  expect(deadline - Date.now()).toBeLessThan(5_000);
});

function cleanup() { vi.useRealTimers(); }

it("a revoking function declared earlier revokes nothing until it is called", () => {
  vi.useFakeTimers();
  const t0 = Date.now();
  expect(Date.now() - t0).toBeLessThan(116);
});
