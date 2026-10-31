// K9 RED: the inner destructure `{ a: W }` binds W again.
const W = 300_000;
function g(o) { const { a: W } = o; return W; }
it("d", async () => {}, W);
