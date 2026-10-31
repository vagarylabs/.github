// One RED per typescript rule: each bound below its kind's floor.
it("option.case", { timeout: 5_000 }, async () => {});
beforeAll(async () => {}, { timeout: 6_000 });
vi.waitFor(() => true, { timeout: 7_000 });
it("registrar.case", async () => {}, 8_000);
beforeEach?.(async () => {}, 9_000);
vi.waitUntil(() => true, 1_000);
async function helper(timeoutMs = 2_000) { return timeoutMs; }
const config = { testTimeout: 3_000, hookTimeout: 4_000 };
