// The project config sets hookTimeout: it is judged once, at the config, never at every hook that inherits it.
import { startDb } from "../unconf/helpers/pg";
beforeAll(async () => { await startDb(); }, 210_000);
afterEach(async () => { await stop(); });
