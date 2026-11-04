import { spawnSync } from "node:child_process";
export const Page = () => (
  <div>
    <h1>Governance & Autonomy</h1>
  </div>
);
export const run = () => spawnSync("git", [], { timeout: 6_000 });
