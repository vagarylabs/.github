import { spawnSync } from "node:child_process";
export const actual = () => spawnSync("git", [], { timeout: 2_000 });
