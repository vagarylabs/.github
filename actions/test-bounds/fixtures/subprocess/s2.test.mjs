// #60 delta L1/L2: a child process called through an alias, and execa itself, are the subprocess kind (120 s).
// Each alias line would clear at the 60 s condition floor if the binding were not resolved.
import { execFile as ef, spawnSync as run } from "node:child_process";
import { promisify } from "node:util";
import { execa, execaNode } from "execa";
const pexec = promisify(ef);
const { exec: ex } = require("child_process");
run("x", [], { timeout: 60_000 });
pexec("x", [], { timeout: 61_000 });
ex("x", { timeout: 62_000 });
execa("x", [], { timeout: 60_000 });
execaNode("x", [], { "timeout": 60_000 });
other({ timeout: 63_000 });
