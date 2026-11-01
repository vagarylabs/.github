// Greens: a zero flush, a sleep in a loop (a poll), a sleep in a mock handler, a sleep with no assertion after it, a
// helper that is more than one sleep, and a helper called with arguments.
import { expect, it, vi } from "vitest";

async function settleTwice() {
  await sleep(10);
  await sleep(10);
}
const pauseFor = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function checkLater() {
  await sleep(10);
  expect(x).toBe(1);
}

it("not a sleep-as-wait", async () => {
  await new Promise((r) => setTimeout(r, 0));
  for (let i = 0; i < 3; i++) {
    if (ready()) break;
    await sleep(20);
  }
  server.use(async () => {
    await sleep(50);
    return reply();
  });
  await settleTwice();
  await pauseFor(30);
  expect(ready()).toBe(true);
  await sleep(10);
}, 120_000);
