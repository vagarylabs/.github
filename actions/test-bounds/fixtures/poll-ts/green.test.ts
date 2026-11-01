// Greens: budgets at or above the floor, budgets owned by a parameter, and loops that are not polls.
import { it } from "vitest";

const POLL_HANG_GUARD_MS = 120_000;
const MANY_TRIES = 2400;

async function waitFor(fn: () => Promise<boolean>, timeoutMs = 120_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await fn()) return;
    await sleep(50);
  }
  throw new Error("waitFor: the condition did not hold within its deadline");
}

async function pollTimes(fn: () => Promise<boolean>, tries: number) {
  for (let i = 0; i < tries; i++) {
    if (await fn()) return;
    await sleep(10);
  }
}

it("long enough, or not a poll", async () => {
  for (let i = 0; i < 1200; i++) {
    if (x) break;
    await sleep(50);
  }
  const t0 = Date.now();
  while (Date.now() - t0 < POLL_HANG_GUARD_MS) {
    if (x) break;
    await sleep(50);
  }
  for (let i = 0; i < MANY_TRIES; i++) {
    if (x) break;
    await sleep(50);
  }
  for (let i = 1; i < 2000; i++) {
    if (x) break;
    await sleep(50);
  }
  for (let i = 0; i < 3; i++) await sleep(10);
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
  await waitFor(async () => true);
  await pollTimes(async () => true, 5);
});
