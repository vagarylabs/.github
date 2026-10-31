// Guard 1 GREEN: one top-level binding, only read elsewhere.
const Z = 300_000;
const twice = Z * 2;
it("c", async () => {}, Z);
