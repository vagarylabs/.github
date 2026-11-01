// Greens: a cap at a named guard at or above the floor, and stimuli (an event injected at time T).
import { it } from "vitest";

const SUBPROCESS_HANG_GUARD_MS = 180_000;

it("caps long enough, or injects an event", async () => {
  setTimeout(() => child.kill("SIGKILL"), SUBPROCESS_HANG_GUARD_MS);
  setTimeout(() => child.stdout.emit("data", Buffer.from("x")), 10);
  setTimeout(() => controller.abort(), 5);
  setTimeout(() => socket.end(), 30);
}, 240_000);
