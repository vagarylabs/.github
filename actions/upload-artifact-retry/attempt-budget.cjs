'use strict';
// attempt-budget.cjs: loaded into actions/upload-artifact's node process by the composite in this directory through
// `NODE_OPTIONS=--require`, on BOTH of its attempts. It arms one timer: when UPLOAD_ATTEMPT_BUDGET_MS passes and the
// upload is still running, the process prints an ::error:: line and exits 1. That exit is what the design needs and
// the runner cannot give otherwise:
//
//   - an upload that hangs (CreateArtifact: 5 attempts x a 3-min socket timeout; a blob chunk: a 5-min stall timer;
//     actions/upload-artifact v4.6.2 dist/upload/index.js :2731, :12583, :2944) can run ~15 min before it FAILS;
//   - a composite's inner steps cannot carry timeout-minutes, and when the CALLING step's timeout-minutes fires, it
//     fires on the whole composite: measured in the control run (README), attempt one ends outcome=failure ("The
//     action has timed out"), the retry step starts into the already-fired timeout and is timed out after 23 ms,
//     before it makes a request, and the calling step fails. No real retry on a stall (vagaris run 43094998692
//     attempt 1: a 309 s hang, then the 7-min job limit; root's R4 of vagary-core #1150 / vagaris #1009, 2026-11-12).
//
// A node exit 1 is a plain step FAILURE ("Process completed with exit code 1"), so attempt one's continue-on-error
// turns it into outcome=failure / conclusion=success and the retry runs with its whole budget ahead of it, inside a
// bound the composite's caller knows.
//
// Contract (held by attempt-budget.test.mjs):
//   UPLOAD_ATTEMPT_BUDGET_MS unset or empty  -> ::error:: and exit 1 at load (the composite always sets it; a process
//                                               that loads this file without it is not running as reviewed)
//   not a decimal integer                    -> ::error:: and exit 1 at load (a mistyped budget never means "no budget")
//   above 2147483647                         -> ::error:: and exit 1 at load (node clamps a larger setTimeout delay to
//                                               1 ms, which would cut a healthy upload at once with a misleading line)
//   "0"                                      -> no timer, one ::notice:: (CONTROL RUNS ONLY: a hang then runs to the
//                                               caller's timeout-minutes, which fails attempt one and times the retry
//                                               out at once; consumer gates refuse a 0 in a workflow)
//   N > 0                                    -> after N ms, ::error:: and exit 1; the timer is unref'd, so an upload
//                                               that finishes first exits as it always did
// Messages go to fd 1 with fs.writeSync (the runner reads ::error::/::notice:: from stdout). The exit never depends on
// the write: on a full non-blocking pipe fs.writeSync throws EAGAIN (measured on macOS by the test, which fills the
// pipe first), the line is then tried on fd 2 and the attempt still exits 1 at its budget.
const fs = require('fs');

const label = process.env.UPLOAD_ATTEMPT_LABEL || 'upload attempt';
const raw = process.env.UPLOAD_ATTEMPT_BUDGET_MS;

function say(line) {
  for (const fd of [1, 2]) {
    try {
      fs.writeSync(fd, line + '\n');
      return;
    } catch {
      // a full or closed pipe: try the other fd; the caller exits whether or not the line was written
    }
  }
}

if (raw === undefined || raw === '') {
  say(`::error::${label}: UPLOAD_ATTEMPT_BUDGET_MS is not set; the upload-artifact-retry composite always sets it, so this process is not running under the composite as reviewed`);
  process.exit(1);
}
if (!/^\d+$/.test(raw)) {
  say(`::error::${label}: UPLOAD_ATTEMPT_BUDGET_MS=${JSON.stringify(raw)} is not a decimal integer of milliseconds; a mistyped budget never means "no budget"`);
  process.exit(1);
}
const MAX_DELAY_MS = 2147483647; // setTimeout's largest delay; node clamps anything above it to 1 ms
const budgetMs = Number(raw);
if (budgetMs > MAX_DELAY_MS) {
  say(`::error::${label}: UPLOAD_ATTEMPT_BUDGET_MS=${raw} is above ${MAX_DELAY_MS} ms, which node would clamp to a 1 ms timer and cut a healthy upload at once`);
  process.exit(1);
}
if (budgetMs === 0) {
  say(`::notice::${label}: no budget (UPLOAD_ATTEMPT_BUDGET_MS=0): a hang runs to the calling step's timeout-minutes, which fails this attempt and times the retry out at once. Control runs only.`);
} else {
  const timer = setTimeout(() => {
    say(`::error::${label} exceeded its ${budgetMs} ms budget and is still running: failing this attempt (exit 1, not a cancel) so the composite's retry can run`);
    process.exit(1);
  }, budgetMs);
  timer.unref();
}
