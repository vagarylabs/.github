import { spawnSync } from "node:child_process";
export const req = () => spawnSync("git", [], { timeout: 2_000 });
