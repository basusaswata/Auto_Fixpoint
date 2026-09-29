const test = require("node:test");
const assert = require("node:assert");
const app = require("../server");

test("app exports a handler", () => {
  assert.strictEqual(typeof app, "function");
});
