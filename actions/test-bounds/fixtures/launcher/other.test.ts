// K16 RED: the same name imported from a module that is not the declared launcher's.
import { startEmbeddedPostgresTestDatabase } from "./helpers/other-pg";
beforeAll(async () => { await startEmbeddedPostgresTestDatabase(); }, 210_000);
