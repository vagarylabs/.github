// The PostgreSQL shorthand property (#65 RC, mutant M65-08): a short value through `{ statement_timeout }`.
const statement_timeout = 4_000;
const client = new Client({ statement_timeout });
