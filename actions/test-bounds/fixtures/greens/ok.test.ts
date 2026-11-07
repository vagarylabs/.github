// GREEN: every compliant form; the check must clear all of these and count none.
import { HOOK_HANG_GUARD_MS } from "./guards";
const TEST_HANG_GUARD_MS = 120_000;
const CONDITION_HANG_GUARD_MS = 60_000;
it("named guard", async () => {}, TEST_HANG_GUARD_MS);
it("literal at the floor", async () => {}, 120_000);
it("arithmetic", async () => {}, 2 * 60_000);
beforeAll(async () => {}, HOOK_HANG_GUARD_MS);
vi.waitFor(() => true, { timeout: CONDITION_HANG_GUARD_MS });
