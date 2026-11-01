// A planted RED in tsx.
it("renders", async () => {
  render(<Panel />);
  await settleView({ deadlineMs: 300 });
}, 120_000);
