// Planted REDs: kill timers that cap a hung child below the 120 s subprocess floor.
import { it } from "vitest";

it("caps a child", async () => {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("the child exceeded 20 s"));
    }, 20_000);
    child.on("exit", () => { clearTimeout(timer); resolve(undefined); });
  });
  setTimeout(() => proc.kill(), 5000);
  setTimeout(() => proc.kill(), 90_000);
  setTimeout(() => { // timeout under test: the child's 2 s budget is the contract this case pins
    child2.kill();
  }, 2_000);
}, 240_000);
