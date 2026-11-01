// A local function that shares the launcher's name is not the declared launcher: no default.hook here.
async function startDb() { return {}; }
it("starts its own", async () => { await startDb(); }, 120_000);
afterEach(async () => { await stop(); });
