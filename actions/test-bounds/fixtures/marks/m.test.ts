it("marked", async () => {}, 5_000); // timeout under test: the 5 s budget IS the behaviour (a latency contract)
it("no reason", async () => {}, 5_000); // timeout under test:
it("unmarked", async () => {}, 5_000);
/* timeout under test: the mark text sits on this line
   */ it("block", async () => {}, 5_000);
it("thin", async () => {}, 5_000); // timeout under test: ...
it("x // timeout under test: a string is not a comment", async () => {}, 5_000);
