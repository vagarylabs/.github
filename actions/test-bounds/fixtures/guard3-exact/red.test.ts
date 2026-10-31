// Guard 3 RED: only literals, unary minus and + - * are evaluated.
const HALF = 600_000 / 2;
const PARSED = Number("300000");
const FROM_ENV = Number(process.env.T ?? 300_000);
it("division", async () => {}, HALF);
it("call", async () => {}, PARSED);
it("env", async () => {}, FROM_ENV);
beforeAll(async () => {}, 0210000);
it("power", async () => {}, 2 ** 19);
