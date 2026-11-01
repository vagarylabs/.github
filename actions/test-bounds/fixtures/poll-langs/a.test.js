// A planted RED in javascript.
it("polls", async () => {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (ready()) break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
});
