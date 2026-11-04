declare const Pool: new (o: object) => object;
export const pool = new Pool({ connectionTimeoutMillis: 2_000 });
