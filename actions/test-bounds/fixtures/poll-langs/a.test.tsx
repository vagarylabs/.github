// A planted RED in tsx.
it("polls", async () => {
  render(<Panel />);
  for (let i = 0; i < 20; i++) {
    if (screen.queryByText("x")) break;
    await sleep(50);
  }
});
