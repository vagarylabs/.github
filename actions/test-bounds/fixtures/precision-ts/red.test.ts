// REDs that the narrowing must keep: web-first assertions, a real `end({ timeout })`, a named zero, a body by name.
import { expect, it } from "vitest";

const ZERO = 0;

it("real bounds stay", async () => {
  await expect(page.getByText("x")).toBeVisible({ timeout: 5_000 });
  await client.end({ timeout: 5 });
  await pool.end({ timeout: ZERO });
}, 120_000);

it("by name", handler, 5_000);
