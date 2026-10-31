// Guard 1 RED: X is bound again in an inner scope, so the use is ambiguous.
const X = 300_000;
function inner() { const X = 1; return X; }
it("a", async () => {}, X);
