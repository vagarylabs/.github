declare const sql: { end(o: { timeout: number }): Promise<void> };
export const close = () => sql.end({ timeout: 5 }); // postgres.js: seconds, excluded by callee
