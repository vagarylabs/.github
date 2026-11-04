import { spawnSync } from "node:child_process";
const GIT_MS = 10_000; // a named constant below the floor is still a finding
export const run = () => spawnSync("git", ["status"], { timeout: 5_000 });
export const named = () => spawnSync("git", ["log"], { timeout: GIT_MS });
export const forwarded = (t: number) => spawnSync("git", ["fetch"], { timeout: t });
