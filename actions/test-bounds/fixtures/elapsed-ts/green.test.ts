// Greens: cleared by value or by a proven fake clock, or not an elapsed upper bound at all.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const LIMIT_MS = 90_000;

it("at or above the floor", () => {
  expect(Date.now() - t0).toBeLessThan(120_000);
  expect(Date.now() - newest.getTime()).toBeLessThan(24 * 3600 * 1000);
  expect((Date.now() - t0) / 1000).toBeLessThan(90);
  const secs = (performance.now() - t0) / 1000;
  expect(secs).toBeLessThan(90);
  expect(Date.now() - t0).toBeLessThan(LIMIT_MS);
  expect(Date.now() - credential.authenticatedAt!.getTime()).toBeLessThan(120_000);
});

it("not an elapsed upper bound", () => {
  expect(Date.now() - t >= 150).toBe(true);
  expect(Date.now() - t0).toBeGreaterThan(5);
  while (Date.now() - startedAt < LIMIT_MS) {}
  expect(deadline - Date.now()).toBeLessThan(5000);
  expect(result.durationMs).toBeLessThan(500);
  expect(Date.now() - t0 < 5).not.toBe(true);
});

it("binds a name to a clock difference and asserts nothing", () => {
  const elapsed = Date.now() - s;
  void elapsed;
});

it("a sibling's clock-bound name", () => {
  const elapsed = compute();
  expect(elapsed).toBeLessThan(5);
});

describe("fake timers from a hook", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });
  it("advances the fake clock", () => {
    const t0 = Date.now();
    vi.advanceTimersByTime(100);
    expect(Date.now() - t0).toBeLessThan(200);
  });
});

it("performance named in toFake", () => {
  vi.useFakeTimers({ toFake: ["performance", "setTimeout"] });
  expect(performance.now() - t0).toBeLessThan(10);
});

it("setSystemTime fakes Date", () => {
  vi.setSystemTime(new Date(2026, 0, 1));
  expect(Date.now() - t0).toBeLessThan(10);
});

function twice() { return Date.now() - t0; }
function twice() { return 0; }
const [hole] = [0];

it("an ambiguous helper, and an array hole, are not read", async () => {
  const x = twice();
  expect(x).toBeLessThan(5);
  const [, gap] = await pair();
  expect(gap).toBeLessThan(5);
});

async function pair() { return [Date.now() - t0, 1]; }
