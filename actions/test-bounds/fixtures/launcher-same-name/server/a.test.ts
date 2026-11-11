// Two declared launchers share a name in different modules (vagaris: server's and packages/db's
// startEmbeddedPostgresTestDatabase). Each hook is judged by the launcher its own import binds, never by whichever rule
// matched last.
import { startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres";
beforeAll(async () => { await startEmbeddedPostgresTestDatabase(); }, 210_000);
