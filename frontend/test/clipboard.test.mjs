import assert from "node:assert/strict";
import test from "node:test";
import { copyOrSelect } from "../src/clipboard.ts";

test("copy with clipboard access, otherwise offer manual selection", async () => {
  let selected = 0;
  const select = () => selected++;
  const success = { writeText: async value => assert.equal(value, "example") };
  assert.equal(await copyOrSelect("example", select, success), true);
  assert.equal(selected, 0);
  assert.equal(await copyOrSelect("example", select, undefined), false);
  const denied = { writeText: async () => { throw new Error("permission denied"); } };
  assert.equal(await copyOrSelect("example", select, denied), false);
  assert.equal(selected, 2);
});
