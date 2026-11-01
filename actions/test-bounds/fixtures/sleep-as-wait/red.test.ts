// Planted REDs: one fixed sleep in a test or hook body, then an assertion.
import { beforeEach, expect, it } from "vitest";

const settle = () => new Promise((r) => setTimeout(r, 150));
async function pauseForTick() {
  await sleep(40);
}

beforeEach(async () => {
  start();
  await sleep(100);
  expect(started()).toBe(true);
});

it("waits a fixed time for an effect", async () => {
  fire();
  await sleep(400);
  expect(await countLive()).toBe(0);
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(seen(), 1);
  await settle();
  expect(done()).toBe(true);
  await pauseForTick();
  try {
    await wait(80);
  } finally {
    cleanup();
  }
  expect(stopped()).toBe(true);
  await sleep(1100); // timeout under test: the JWT iat claim moves on a one-second boundary
  expect(token()).not.toBe(old);
});
