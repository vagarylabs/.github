// B5: child-process timeouts are the subprocess kind (120 s), as in Python.
import { spawnSync, execFileSync } from "node:child_process";
spawnSync("bash", ["-c", "x"], { encoding: "utf8", timeout: 60_000 });
child_process.execFileSync("x", [], { timeout: 90_000 });
execFileSync("x", [], { timeout: 120_000 });
