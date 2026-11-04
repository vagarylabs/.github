import { spawnSync } from "node:child_process";
export const mocked = () => spawnSync("git", [], { timeout: 2_000 });
