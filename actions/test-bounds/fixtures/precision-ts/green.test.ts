// Greens (the vagaris hardening branch, f2961a44f): data, expected values and describe-named helpers are not bounds.
import { expect, it } from "vitest";

it("data, not bounds", async () => {
  await pool.end({ timeout: 0 });
  expect(options).toEqual({ timeout: 12_345 });
  expect(call).toHaveBeenCalledWith({ timeout: 1 });
  expect(cfg).toMatchObject({ timeout: 5 });
  describeExit("wsl", 4);
}, 120_000);
