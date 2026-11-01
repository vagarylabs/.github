// The file sets its own hookTimeout (vi.setConfig): judged there, not at the hook.
import { startDb } from "../unconf/helpers/pg";
vi.setConfig({ hookTimeout: 300_000 });
beforeAll(async () => { await startDb(); }, 210_000);
afterEach(async () => { await stop(); });
