// No vitest config up the tree: the runner is unknown, so default.hook judges nothing here.
import { startDb } from "../unconf/helpers/pg";
beforeAll(async () => { await startDb(); }, 210_000);
afterEach(async () => { await stop(); });
