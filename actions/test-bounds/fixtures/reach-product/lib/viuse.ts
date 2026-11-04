declare const vi: { waitFor(fn: () => unknown, o: { timeout: number }): Promise<unknown> };
export const w = () => vi.waitFor(() => 1, { timeout: 2_000 });
