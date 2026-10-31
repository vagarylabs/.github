// Guard 2 RED: the source declares the export twice, so its one binding is not proven.
import { G } from "./two";
it("a", async () => {}, G);
