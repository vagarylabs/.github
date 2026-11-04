import { it } from "vitest";
// A shared suite is test code wherever it lives: its case bound is judged.
export function suite() {
  it("shared", () => {}, 5_000);
}
