declare function describe(name: string, fn: () => void, timeout?: number): void;
// Test code that imports no framework (the runner injects the globals): an exact global API makes it support.
export const wire = () => describe("wired", () => undefined, 1_000);
