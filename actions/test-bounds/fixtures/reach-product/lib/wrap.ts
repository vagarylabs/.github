import { execFile } from "node:child_process";
// A same-file wrapper that forwards its options to a child process (vagaris ssh.ts:196 and :911). The 90 s call below
// sits between the condition floor and the subprocess floor: a finding only when the wrapper is read as a child process.
async function execFileText(file: string, args: string[], options: { timeout?: number } = {}): Promise<string> {
  return await new Promise<string>((resolve) => {
    execFile(file, args, { timeout: options.timeout ?? 15_000 }, (_e, stdout) => resolve(String(stdout)));
  });
}
export const readPs = () => execFileText("ps", ["-o", "args="], { timeout: 90_000 });
export const fallback = (a: number, b: number) => a || b || 20_000; // not a bound: no timeout position
