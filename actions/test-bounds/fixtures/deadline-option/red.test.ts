// Planted REDs: deadline options passed into the code under test, below the 60 s condition floor.
import { it } from "vitest";

const SHORT_GRACE_MS = 100;

it("passes short deadlines in", async () => {
  await worker.stop({ drainTimeoutMs: 50 });
  await run({ deadlineMs: 2_000 });
  await plan({ "budgetMs": 500 });
  await stop({ graceTimeoutMs: SHORT_GRACE_MS });
}, 120_000);
