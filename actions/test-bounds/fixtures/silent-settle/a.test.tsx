// A planted RED in tsx.
async function settleUi(timeoutMs = 2000) {
  const s = Date.now();
  while (Date.now() - s < timeoutMs) {
    await new Promise((r) => setTimeout(r, 5));
  }
}
it("renders", async () => {
  render(<Panel />);
  await settleUi();
}, 120_000);
