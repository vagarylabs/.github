// Greens: a helper that throws at its deadline, one that returns its result, one with no deadline loop.
import { it } from "vitest";

async function waitUntil(timeoutMs = 120_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await ok()) return;
    await sleep(25);
  }
  throw new Error("timed out");
}
async function settleOrFalse(timeoutMs = 120_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await ok()) return true;
    await sleep(25);
  }
  return false;
}
async function delayOnly(timeoutMs = 120_000) {
  await sleep(timeoutMs);
}

async function retry(timeoutMs = 120_000) {
  for (let i = 0; i < 3; i++) await sleep(1);
}
async function quietLoop(quietMs = 100) {
  const s = Date.now();
  while (Date.now() - s < quietMs) await sleep(1);
}

it("conditions", async () => {
  await waitUntil();
  await settleOrFalse();
  await delayOnly();
  await retry();
  await quietLoop();
}, 120_000);
