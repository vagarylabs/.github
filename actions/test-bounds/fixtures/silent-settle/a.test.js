// A planted RED in javascript.
async function quietDown(deadlineMs = 2000) {
  const s = Date.now();
  while (Date.now() - s < deadlineMs) {
    await sleep(5);
  }
}
async function quietJs(quietMs = 100) {
  const s = Date.now();
  while (Date.now() - s < quietMs) await sleep(1);
}
test("drains", async () => {
  await quietDown();
  await quietJs();
}, 120_000);
