// A planted RED in javascript.
it("drains", async () => {
  await queue.close({ drainTimeoutMs: 25 });
}, 120_000);
