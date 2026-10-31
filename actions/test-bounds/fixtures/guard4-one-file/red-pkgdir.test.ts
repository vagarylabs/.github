// L6 RED: "./pkgdir" holds a package.json; index.ts may not be what loads.
import { P } from "./pkgdir";
it("p", async () => {}, P);
