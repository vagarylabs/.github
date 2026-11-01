// A planted RED in tsx.
it("caps", async () => {
  render(<Panel />);
  setTimeout(() => worker.kill(), 1000);
}, 240_000);
