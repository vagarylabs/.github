// Product-shaped bounds a reached module may hold: a call's generic timeout option (read), a timeout-named default
// that feeds no bound (not read), and a
// product function whose name a test registrar's pattern would read (`describe\w*`).
declare function request(o: { timeout: number }): Promise<void>;
declare function describeStaleness(a: number, b: number, c: number): string;
export async function settle(timeoutMs = 5_000) {
  await request({ timeout: 3_000 });
  describeStaleness(1, 2, 3);
  return timeoutMs;
}
