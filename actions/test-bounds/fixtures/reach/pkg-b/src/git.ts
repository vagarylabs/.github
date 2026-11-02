import { execFileSync } from "node:child_process";
// Built to dist/, tracked as src/: the export map names dist/git.js.
export const head = () => execFileSync("git", ["rev-parse", "HEAD"], { timeout: 4_000 });
