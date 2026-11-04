import { execFile } from "node:child_process";
import { promisify } from "node:util";
// promisify(<child process>)(...) is a child process call (vagaris executor-registry.ts:275). 90 s sits between the
// condition floor and the subprocess floor, so this is a finding only when the call is read as a child process.
export const codex = async () => (await promisify(execFile)("codex", ["--help"], { timeout: 90_000 })).stdout;
