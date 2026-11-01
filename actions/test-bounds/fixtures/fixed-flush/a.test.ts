// A planted RED in typescript: a helper that calls a turn helper is one (the closure).
const turn = () => new Promise<void>((r) => setTimeout(r, 0));
async function drainQueue() {
  await turn();
  await turn();
}
it("drains", async () => {
  await drainQueue();
});
