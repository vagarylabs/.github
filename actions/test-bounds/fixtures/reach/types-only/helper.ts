import { execFileSync } from "node:child_process";
export type Shape = { a: number };
execFileSync("ps", [], { timeout: 1_000 });
