import { execFile } from "node:child_process";
import { promisify } from "node:util";
// promisify(<child process>)(...) is a child process call (vagaris executor-registry.ts:275).
export const codex = async () => (await promisify(execFile)("codex", ["--help"], { timeout: 10_000 })).stdout;
