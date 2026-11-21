// node --test actions/upload-artifact-retry/attempt-budget.test.mjs
// Holds attempt-budget.cjs's contract (header of that file) by running real node processes under NODE_OPTIONS, the way
// the runner loads it, and pins the composite's shape in action.yml (both attempts carry the preload and a budget from
// their own input; attempt one is continue-on-error and never overwrites; the retry runs on failure only and
// overwrites; one upload-artifact sha on both; every input passes through to both).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const preload = join(here, 'attempt-budget.cjs');
const actionYml = readFileSync(join(here, 'action.yml'), 'utf8');

// A hanging "upload": an interval keeps the event loop alive until something exits the process.
const HANG = 'setInterval(() => {}, 1000); console.log("hang: started");';
const QUICK = 'console.log("quick: done");';

// `readAfterMs`: leave the child's stdout pipe unread for that long (the stream stays paused until a data listener is
// attached), so a child that writes more than the pipe holds is blocked on a full pipe when its budget fires.
function run(script, env, { killAfterMs, nodeOptions, readAfterMs = 0 } = {}) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, ['-e', script], {
      env: { ...process.env, NODE_OPTIONS: nodeOptions ?? `--require "${preload}"`, UPLOAD_ATTEMPT_LABEL: 'test attempt', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    setTimeout(() => child.stdout.on('data', (d) => { out += d; }), readAfterMs);
    child.stderr.on('data', (d) => { err += d; });
    let killed = false;
    let killer;
    if (killAfterMs) killer = setTimeout(() => { killed = true; child.kill('SIGKILL'); }, killAfterMs);
    child.on('close', (code, signal) => {
      clearTimeout(killer);
      resolve({ code, signal, killed, out, err, ms: Date.now() - started });
    });
  });
}

test('a hang is FAILED (exit 1, ::error::) once the budget passes', async () => {
  const r = await run(HANG, { UPLOAD_ATTEMPT_BUDGET_MS: '400' }, { killAfterMs: 15000 });
  assert.equal(r.killed, false, 'the preload, not the test, ended the process');
  assert.equal(r.code, 1);
  assert.match(r.out, /^::error::test attempt exceeded its 400 ms budget and is still running: failing this attempt \(exit 1, not a cancel\)/m);
  assert.ok(r.ms >= 400, `exited at ${r.ms} ms, before the budget`);
  assert.ok(r.ms < 10000, `exited at ${r.ms} ms, long after the budget`);
});

test('an upload that finishes inside its budget exits as it always did (the timer holds nothing open)', async () => {
  const r = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: '20000' }, { killAfterMs: 15000 });
  assert.equal(r.killed, false);
  assert.equal(r.code, 0);
  assert.match(r.out, /quick: done/);
  assert.doesNotMatch(r.out, /::error::/);
  assert.ok(r.ms < 5000, `a 20 s budget held the process ${r.ms} ms`);
});

test('budget 0 arms nothing: a hang runs on (control runs only), with one ::notice::', async () => {
  const r = await run(HANG, { UPLOAD_ATTEMPT_BUDGET_MS: '0' }, { killAfterMs: 1500 });
  assert.equal(r.killed, true, 'the process should still be hanging when the test kills it');
  assert.match(r.out, /^::notice::test attempt: no budget \(UPLOAD_ATTEMPT_BUDGET_MS=0\).*Control runs only\./m);
  assert.doesNotMatch(r.out, /::error::/);
});

test('an unset budget fails the process at load: the preload never runs outside the composite as reviewed', async () => {
  const r = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: undefined }, { killAfterMs: 15000 });
  assert.equal(r.code, 1);
  assert.match(r.out, /^::error::test attempt: UPLOAD_ATTEMPT_BUDGET_MS is not set/m);
  assert.doesNotMatch(r.out, /quick: done/, 'the upload code must not run without a budget');
});

for (const bad of ['', '12a', '1.5', '-1', ' 100', '1e3']) {
  test(`a budget of ${JSON.stringify(bad)} fails the process at load (a mistyped budget never means "no budget")`, async () => {
    const r = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: bad }, { killAfterMs: 15000 });
    assert.equal(r.code, 1, r.out + r.err);
    assert.match(r.out, bad === '' ? /is not set/ : /is not a decimal integer of milliseconds/);
    assert.doesNotMatch(r.out, /quick: done/);
  });
}

test('a budget above 2147483647 ms fails the process at load (node would clamp the timer to 1 ms and cut a healthy upload)', async () => {
  const r = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: '2147483648' }, { killAfterMs: 15000 });
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.out, /^::error::test attempt: UPLOAD_ATTEMPT_BUDGET_MS=2147483648 is above 2147483647 ms/m);
  assert.doesNotMatch(r.out, /quick: done/);
  assert.doesNotMatch(r.out, /exceeded its/);
});

test('a budget of exactly 2147483647 ms is accepted and holds nothing open', async () => {
  const r = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: '2147483647' }, { killAfterMs: 15000 });
  assert.equal(r.killed, false);
  assert.equal(r.code, 0, r.out + r.err);
  assert.match(r.out, /quick: done/);
  assert.doesNotMatch(r.out, /::error::/);
});

test('a full stdout pipe at the budget still exits the attempt 1 at the budget (the exit does not depend on the message write)', async () => {
  // The "upload" queues 4 MiB on stdout (more than any pipe holds) and hangs; nothing reads the pipe for 1.5 s, so
  // when the 400 ms budget fires the preload's fs.writeSync meets a full non-blocking pipe and throws EAGAIN (macOS;
  // on Linux the stdout pipe is synchronous and the write blocks until the reader drains it). Either way the attempt
  // must exit 1 at its budget, by itself, with no uncaught exception: the line may be lost, the failure may not.
  const FILL_THEN_HANG = 'process.stdout.write("x".repeat(4 * 1024 * 1024) + "\\n"); setInterval(() => {}, 1000);';
  const r = await run(FILL_THEN_HANG, { UPLOAD_ATTEMPT_BUDGET_MS: '400' }, { killAfterMs: 20000, readAfterMs: 1500 });
  assert.equal(r.killed, false, 'the preload, not the test, ended the process');
  assert.equal(r.code, 1, r.err);
  assert.doesNotMatch(r.err, /EAGAIN|Uncaught|at Timeout/, 'a failed write must be caught, not thrown out of the timer');
  assert.ok(r.ms >= 400 && r.ms < 10000, `exited at ${r.ms} ms`);
});

// ---- the preload path (B1 of root's R4: a backslash inside NODE_OPTIONS quotes is an escape) ----

test('a backslash in the preload directory name breaks `--require "..."`: MODULE_NOT_FOUND before the upload runs, so the path is slash-normalised first', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'uar-'));
  try {
    const sub = join(dir, 'a\\b'); // the P1b form: one backslash in the directory name
    mkdirSync(sub);
    copyFileSync(preload, join(sub, 'attempt-budget.cjs'));
    const broken = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: '20000' }, { killAfterMs: 15000, nodeOptions: `--require "${join(sub, 'attempt-budget.cjs')}"` });
    assert.notEqual(broken.code, 0, 'node loaded a path whose backslash was read as an escape');
    assert.match(broken.err, /MODULE_NOT_FOUND|Cannot find module/);
    assert.doesNotMatch(broken.out, /quick: done/, 'the upload must not run without the preload');
    // The same file reached by a path without a backslash loads (the hazard is the separator, not the copy).
    const plain = join(dir, 'plain');
    mkdirSync(plain);
    copyFileSync(preload, join(plain, 'attempt-budget.cjs'));
    const ok = await run(QUICK, { UPLOAD_ATTEMPT_BUDGET_MS: '20000' }, { killAfterMs: 15000, nodeOptions: `--require "${join(plain, 'attempt-budget.cjs')}"` });
    assert.equal(ok.code, 0, ok.out + ok.err);
    assert.match(ok.out, /quick: done/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

function preloadStepRun(yml) {
  const [preloadStep] = steps(yml);
  const m = preloadStep.match(/\n      run: (.+)\n/);
  assert.ok(m, 'the preload step has a one-line run:');
  return m[1];
}

test('the preload step writes the slash-normalised action path to GITHUB_OUTPUT (the action.yml run line itself, under bash)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'uar-out-'));
  try {
    const cases = [
      ['D:\\a\\_actions\\vagarylabs\\.github\\0123abcd\\actions\\upload-artifact-retry', 'D:/a/_actions/vagarylabs/.github/0123abcd/actions/upload-artifact-retry'],
      ['/home/runner/_work/_actions/vagarylabs/.github/0123abcd/actions/upload-artifact-retry', '/home/runner/_work/_actions/vagarylabs/.github/0123abcd/actions/upload-artifact-retry'],
      ['/tmp/sp ace/upload-artifact-retry', '/tmp/sp ace/upload-artifact-retry'],
    ];
    for (const [actionPath, normalised] of cases) {
      const outFile = join(dir, 'out.txt');
      rmSync(outFile, { force: true });
      const r = spawnSync('bash', ['-euo', 'pipefail', '-c', preloadStepRun(actionYml)], {
        env: { PATH: process.env.PATH, ACTION_PATH: actionPath, GITHUB_OUTPUT: outFile }, encoding: 'utf8',
      });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(readFileSync(outFile, 'utf8'), `file=${normalised}/attempt-budget.cjs\n`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the preload step reads github.action_path through its env only, and no other step names github.action_path', () => {
  const [preloadStep, first, retry] = steps(actionYml);
  assert.match(preloadStep, /\n      id: preload\n/);
  assert.match(preloadStep, /\n      shell: bash\n/);
  assert.match(preloadStep, /\n        ACTION_PATH: \$\{\{ github\.action_path \}\}\n/);
  assert.doesNotMatch(preloadStep, /run: .*\$\{\{/, 'no expression inside the run line');
  assert.doesNotMatch(preloadStep, /GITHUB_ENV/);
  assert.match(preloadStep, /GITHUB_OUTPUT/);
  assert.doesNotMatch(first + retry, /github\.action_path/);
});

// ---- the composite's shape ----

function steps(yml) {
  // The three `- name:` blocks under runs.steps, as text: the preload path, attempt one, the retry.
  const body = yml.slice(yml.indexOf('\n  steps:\n'));
  const parts = body.split(/\n    - name: /).slice(1).map((p) => p.endsWith('\n') ? p : p + '\n');
  assert.equal(parts.length, 3, 'exactly three steps: the preload path, attempt one and the retry');
  assert.match(parts[0], /^Preload path/);
  return parts;
}

test('both attempts load the preload through NODE_OPTIONS from the preload step output, keep a job-level NODE_OPTIONS, and take their budget from their own input', () => {
  const [, first, retry] = steps(actionYml);
  for (const s of [first, retry]) {
    assert.match(s, /NODE_OPTIONS: \$\{\{ env\.NODE_OPTIONS \}\} --require "\$\{\{ steps\.preload\.outputs\.file \}\}"/);
  }
  assert.match(first, /UPLOAD_ATTEMPT_BUDGET_MS: \$\{\{ inputs\.attempt-budget-ms \}\}/);
  assert.match(retry, /UPLOAD_ATTEMPT_BUDGET_MS: \$\{\{ inputs\.retry-budget-ms \}\}/);
  assert.doesNotMatch(first, /retry-budget-ms/);
  assert.doesNotMatch(retry, /attempt-budget-ms/);
});

test('attempt one is continue-on-error and never overwrites; the retry runs only on a failed attempt one and overwrites', () => {
  const [, first, retry] = steps(actionYml);
  assert.match(first, /\n      id: first\n/);
  assert.match(first, /\n      continue-on-error: true\n/);
  assert.doesNotMatch(first, /overwrite/);
  assert.doesNotMatch(first, /\n      if:/);
  assert.match(retry, /\n      if: \$\{\{ steps\.first\.outcome == 'failure' \}\}\n/);
  assert.match(retry, /\n        overwrite: true\n/);
  assert.doesNotMatch(retry, /continue-on-error/);
});

test('one upload-artifact sha on both attempts, and it is the v4.6.2 commit', () => {
  const uses = [...actionYml.matchAll(/^\s+uses: actions\/upload-artifact@([0-9a-f]{40}) # v([\d.]+)$/gm)];
  assert.equal(uses.length, 2);
  assert.equal(uses[0][1], uses[1][1]);
  assert.equal(uses[0][1], 'ea165f8d65b6e75b540449e92b4886f43607fa02');
  assert.equal(uses[0][2], '4.6.2');
  assert.doesNotMatch(actionYml, /uses: actions\/upload-artifact@v/, 'no floating tag');
});

test('every declared input passes through to both attempts; the budgets are decimal-integer defaults; 0 is documented as control-only', () => {
  const inputs = [...actionYml.matchAll(/^  ([a-z-]+):\n    description:/gm)].map((m) => m[1]);
  assert.deepEqual(inputs, ['name', 'path', 'if-no-files-found', 'retention-days', 'include-hidden-files', 'attempt-budget-ms', 'retry-budget-ms']);
  const [, first, retry] = steps(actionYml);
  for (const inp of ['name', 'path', 'if-no-files-found', 'retention-days', 'include-hidden-files']) {
    const re = new RegExp(`\\n        ${inp}: \\$\\{\\{ inputs\\.${inp} \\}\\}\\n`);
    assert.match(first, re, `${inp} on attempt one`);
    assert.match(retry, re, `${inp} on the retry`);
  }
  assert.match(actionYml, /attempt-budget-ms:[\s\S]*?default: '150000'/);
  assert.match(actionYml, /retry-budget-ms:[\s\S]*?default: '150000'/);
  assert.match(actionYml, /"0" disables the budget and is\n\s+for control runs only: consumer gates refuse it in a workflow/);
});
