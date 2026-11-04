import { execFileSync } from "node:child_process";
// The shape that reddened vagaris main 17464b2f: a literal ps timeout in a helper a test loads.
export const command = (pid: number) => execFileSync("ps", ["-o", "command=", "-p", String(pid)], {
  encoding: "utf8", timeout: 2_000, maxBuffer: 16 * 1024,
});
