// Planted REDs in tsx.
const flushLater = () => new Promise((r) => setTimeout(r, 50));
it("debounces", async () => {
  render(<Search />);
  await sleep(300);
  expect(screen.getByText("x")).toBeTruthy();
  await flushLater();
  expect(screen.getByText("y")).toBeTruthy();
}, 120_000);
