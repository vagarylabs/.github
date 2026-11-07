// #60 delta2 LOW: the rarer child-process alias forms. Each would clear at the 60 s condition floor if the binding
// were not resolved; resolved, each is the subprocess kind (120 s) and stays a finding.
import cp, { execFile as ef2 } from "node:child_process";
import * as ns from "child_process";
import { promisify } from "node:util";
let { spawn: sp } = require("child_process");
const mod = require("child_process");
const run2 = cp.spawnSync;
const run3 = mod.execSync;
const pexec2 = promisify(ns.execFile);
ef2("x", [], { timeout: 64_000 });
sp("x", [], { timeout: 65_000 });
run2("x", [], { timeout: 66_000 });
run3("x", { timeout: 67_000 });
pexec2("x", [], { timeout: 68_000 });
const notCp = other.spawnSync;
notCp("x", { timeout: 69_000 });
