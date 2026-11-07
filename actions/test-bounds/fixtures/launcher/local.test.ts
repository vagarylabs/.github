// RED: a local function of the same name is not the launcher's binding.
async function startEmbeddedPostgresTestDatabase() {}
beforeAll(async () => { await startEmbeddedPostgresTestDatabase(); }, 210_000);
