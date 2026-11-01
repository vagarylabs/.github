// Greens: turns inside React's own act(), a non-zero sleep, helpers awaited in nested callbacks, a helper with args.
import { act } from "react";
import { act as reactAct } from "react-dom/test-utils";
import { it, vi } from "vitest";

const flushReact = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });
const pause = () => new Promise((r) => setTimeout(r, 25));
const drain = (n: number) => new Promise((r) => setTimeout(r, 0));
const flushAliased = () => reactAct(async () => { await new Promise((r) => setTimeout(r, 0)); });
const turn = () => new Promise((r) => setTimeout(r, 0));

it("deterministic or not a turn", async () => {
  await flushReact();
  await flushAliased();
  await pause();
  await drain(3);
  await vi.waitFor(async () => {
    await turn();
  });
  [1, 2].forEach(async () => {
    await turn();
  });
});
