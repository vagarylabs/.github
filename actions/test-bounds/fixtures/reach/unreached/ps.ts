import { execFileSync } from "node:child_process";
export const ps = () => execFileSync("ps", [], { timeout: 2_000 });
