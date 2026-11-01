// Planted REDs: poll loops whose budget is below the 60 s condition floor.
import { expect, it } from "vitest";

const READY_MS = 30_000;

it("counted polls", async () => {
  for (let i = 0; i < 50; i++) {
    if (await ready()) break;
    await sleep(20);
  }
  for (let i = 0; i < 10; i++) {
    if (done) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  for (let i = 0; i < 30 && !done; i++) {
    await sleep(100);
  }
});

it("deadline polls", async () => {
  const startedAt = Date.now();
  while (Date.now() - startedAt < 5_000) {
    if (ok()) break;
    await sleep(50);
  }
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (ok()) break;
    await sleep(50);
  }
  while (performance.now() - startedAt < READY_MS) {
    await sleep(25);
  }
  const deadline2 = Date.now() + 2000;
  do {
    await sleep(25);
  } while (Date.now() < deadline2);
  for (let i = 0; i < 40; i++) { // timeout under test: the 1 s budget is the contract under test
    if (ok()) break;
    await sleep(25);
  }
});
