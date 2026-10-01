import test from "node:test";
import assert from "node:assert/strict";
import { Galleton, ManagedResponse } from "./dist/index.js";

test("rejects remote daemon URLs and credential-bearing URLs", () => {
  for (const baseURL of ["https://example.com", "http://localhost:8766", "http://user:pass@127.0.0.1:8766", "http://127.0.0.1:8766/path"]) {
    assert.throws(() => new Galleton({ token: "local", baseURL }));
  }
});
test("accepts literal loopback URLs", () => {
  new Galleton({ token: "local" });
  new Galleton({ token: "local", baseURL: "http://[::1]:8766" });
});
test("rejects invalid IDs without a network request", () => {
  const c = new Galleton({ token: "local" });
  assert.throws(() => c.status("../other"));
});
test("response preserves binary and JSON bodies", () => {
  const body = new TextEncoder().encode('{"ok":true}');
  const r = new ManagedResponse(200, {}, body, 1);
  assert.equal(r.ok, true); assert.deepEqual(r.json(), { ok: true });
});
test("does not accept newline-bearing API tokens", () => {
  assert.throws(() => new Galleton({ token: "bad\r\ninjection" }));
});
