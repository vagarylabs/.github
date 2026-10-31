// RECOVERED (tree-sitter-typescript #367): the ERROR holds only punctuation. A bound literal in the SAME call
// expression as the recovered ERROR must still be found (root's R2).
vi.waitFor(async () => { await importOriginal<typeof import("./x")>(); }, { timeout: 5_000 });
