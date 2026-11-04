import { command } from "./ssh-fixture-process.js";
export const owner = (pid: number) => command(pid);
