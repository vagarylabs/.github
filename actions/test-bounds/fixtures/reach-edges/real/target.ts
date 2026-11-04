import { spawnSync } from "node:child_process";
export const target = () => spawnSync("git", [], { timeout: 2_000 });
