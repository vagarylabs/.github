// Planted REDs: each assert puts an upper bound below 60 s on a real-clock elapsed difference.
import { expect, it, vi } from "vitest";

it("direct", async () => {
  const started = Date.now();
  await work();
  expect(Date.now() - started).toBeLessThan(1_000);
  expect(Date.now() - started, "with a message").toBeLessThanOrEqual(2500);
  expect(Date.now() - started).not.toBeGreaterThan(300);
  assert.ok(Date.now() - started < 900);
  expect(Date.now() - started < 500).toBe(true);
  expect(800 > performance.now() - started).toBeTruthy();
  expect(Date.now() - started).toBeLessThan(10); // timeout under test: a mark never exempts an elapsed assert
  expect(Date.now() - session!.createdAt.getTime()).toBeLessThan(500);
});

it("named, through a clock-bound name, and scaled", async () => {
  const start = Date.now();
  const t0 = performance.now();
  await work();
  const elapsed = Date.now() - start;
  expect(elapsed).toBeLessThan(1000);
  const t1 = performance.now();
  expect(t1 - t0).toBeLessThan(100);
  const secs = (performance.now() - t0) / 1000;
  expect(secs).toBeLessThan(2);
  expect((Date.now() - start) / 1000).toBeLessThan(5);
  expect((Date.now() - start) / SCALE).toBeLessThan(90_000);
  expect(process.hrtime.bigint() - h0).toBeLessThan(5_000_000_000n);
});

it("a binding inside a preceding try, and a partial sibling nearer the assert", async () => {
  const s = Date.now();
  let took;
  try {
    await work();
  } finally {
    took = Date.now() - s;
  }
  expect(took).toBeLessThan(50);
  const end = performance.now();
  const gap = end - s;
  const decoy = foo - s;
  expect(gap).toBeLessThan(5);
});

it("fake clocks that prove nothing", () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  expect(Date.now() - t0).toBeLessThan(20);
  expect(performance.now() - t0).toBeLessThan(20);
});

it("a sibling test faked the clock", () => {
  vi.useFakeTimers();
  vi.useRealTimers();
});

it("real again", () => {
  expect(Date.now() - t0).toBeLessThan(30);
});

it("faked, then real", () => {
  vi.useFakeTimers();
  vi.useRealTimers();
  expect(Date.now() - t0).toBeLessThan(40);
});

it("no-argument fake timers do not prove performance", () => {
  vi.useFakeTimers();
  expect(performance.now() - t0).toBeLessThan(50);
});
