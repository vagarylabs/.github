// K2 default.hook: in a file that starts a declared launcher, under a vitest config that sets no hookTimeout, a hook
// with no explicit bound runs at vitest's 10 s default. Two REDs; the bounded hooks are judged as usual.
import { startDb } from "./helpers/pg";
async function cluster() { return startDb(); }
beforeAll(async () => { await startDb(); }, 210_000);
afterEach(async () => { await stop(); });
afterAll(async () => { await stop(); }, 240_000);
beforeEach(async () => { await cluster(); });
