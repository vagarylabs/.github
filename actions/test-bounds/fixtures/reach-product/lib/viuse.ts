declare const vi: { waitFor(fn: () => unknown, ms: number): Promise<unknown> };
export const w = () => vi.waitFor(() => 1, 2_000);
