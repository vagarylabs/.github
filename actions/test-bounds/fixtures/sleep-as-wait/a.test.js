// Planted REDs in javascript.
async function nap() {
  await delay(25);
}
test("expires", async () => {
  await delay(1200);
  assert.ok(expired());
  await nap();
  assert.ok(gone());
}, 120_000);
