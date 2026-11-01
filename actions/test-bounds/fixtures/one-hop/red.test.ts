// One hop only: every one of these stays a finding.
import { R } from "./reexport";
import * as G from "./g";
import D from "./d";
import { P } from "some-package";
import { TWO } from "./twohop";
import type { T } from "./g";
it("re-export", async () => {}, R);
it("namespace", async () => {}, G.X);
it("default", async () => {}, D);
it("package", async () => {}, P);
it("two hops", async () => {}, TWO);
it("type-only", async () => {}, T);
