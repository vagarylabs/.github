// The launcher class: a beforeAll whose first argument calls the launcher, imported from the declared module, is
// judged against the launcher's own floor (210 000 ms), not the 240 s hook floor.
import { startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres";
beforeAll(async () => { await startEmbeddedPostgresTestDatabase(); }, 210_000);
beforeAll(async () => { await startEmbeddedPostgresTestDatabase(); }, 200_000);
beforeAll(async () => { await somethingElse(); }, 210_000);
