// Planted REDs: awaited calls of turn helpers directly in a test or hook body, outside React's act().
import { act as reactAct } from "react";
import { beforeEach, expect, it } from "vitest";

async function act(callback: () => void | Promise<void>) {
  await callback();
  await new Promise((resolve) => setTimeout(resolve, 0));
}
const flush = () => new Promise((r) => setTimeout(r));
const settle = async () => {
  for (let i = 0; i < 8; i++) await flush();
};
const flushLocal = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });
const tick = () => new Promise((r) => setImmediate(r));

beforeEach(async () => {
  await tick();
});

it("renders after a fixed count of turns", async () => {
  render(<Panel />);
  await flush();
  await settle();
  expect(screen.getByText("x")).toBeTruthy();
  await flush(); // timeout under test: one turn is the contract this case pins
});

it("a file-local act is a turn helper, but a call with arguments is not a flush count", async () => {
  await act(async () => {});
  await flushLocal();
  const local = async () => { await reactAct(async () => {}); };
  await local();
});
