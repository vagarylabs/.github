// Greens: a zero (none), a deadline at or above the floor, an expected value, a shorthand, a key that is not a bound.
import { expect, it } from "vitest";

it("not short deadlines", async () => {
  await worker.stop({ drainTimeoutMs: 0 });
  await run({ deadlineMs: 120_000 });
  expect(opts).toEqual({ deadlineMs: 5 });
  await run({ deadlineMs });
  await log({ timeoutMsg: 5 });
  await poll({ intervalMs: 10 });
}, 120_000);
