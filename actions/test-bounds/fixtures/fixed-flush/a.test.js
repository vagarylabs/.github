// A planted RED in javascript.
const flushMicro = () => new Promise((r) => setImmediate(r));
test("settles", async () => {
  await flushMicro();
});
