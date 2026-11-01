// Guard 4 RED: "./dup" resolves to two files, "./missing" to none.
import { A } from "./dup";
import { B } from "./missing";
it("two files", async () => {}, A);
it("no file", async () => {}, B);
