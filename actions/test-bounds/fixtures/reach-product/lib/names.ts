declare function describeStaleness(a: number, b: number, c: number): string;
export { describeStaleness };
export const stale = () => describeStaleness(1, 2, 3_000); // a product function, not a test registrar
