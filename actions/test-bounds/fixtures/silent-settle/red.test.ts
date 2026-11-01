// Planted REDs: calls of silent settles outside afterEach/afterAll (and their short defaults, as literal-bound).
import { afterEach, it } from "vitest";

async function settled(timeoutMs = 20_000, quietMs = 1000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await quiet(quietMs)) return;
    await sleep(25);
  }
}
const waitForSideEffects = async (budgetMs = 5_000) => {
  const deadline = Date.now() + budgetMs;
  do {
    await sleep(10);
  } while (pending() && Date.now() < deadline);
};

async function settleQuietly(timeoutMs = 3_000) {
  const start = Date.now();
  const check = () => {
    if (broken()) throw new Error("broken");
  };
  while (Date.now() - start < timeoutMs) {
    check();
    await sleep(5);
  }
}

it("waits silently", async () => {
  await settled();
  await waitForSideEffects();
  await settleQuietly();
  await settled(1000); // timeout under test: the quiet window is the contract this case pins
});

afterEach(async () => {
  await settled();
});
