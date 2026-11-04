import { execFileSync } from "node:child_process";
// A literal parameter default that feeds a child process bound (vagaris baseline.ts:71): judged as that bound.
export function git(args: string[], timeoutMs = 10_000): string {
  return execFileSync("git", args, { timeout: timeoutMs }).toString();
}
// A default that feeds no judged bound stays out of a product module.
export function idle(timeoutMs = 1_000) {
  return timeoutMs;
}
