// Guard 3 RED: only literals, unary minus and + - * are evaluated.
const HALF = 600_000 / 2;
const PARSED = Number("300000");
const FROM_ENV = Number(process.env.T ?? 300_000);
it("division", async () => {}, HALF);
it("call", async () => {}, PARSED);
it("env", async () => {}, FROM_ENV);
it("legacy octal is never read as 210 000 (which would clear the 120 s case floor)", async () => {}, 0210000);
it("power", async () => {}, 2 ** 19);
