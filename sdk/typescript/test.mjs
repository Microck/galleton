import test from "node:test";
import assert from "node:assert/strict";
import { Galleton, GalletonError, ManagedResponse } from "./dist/index.js";

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

test("body-read failures preserve status and uncertain completion", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const failure of [new TypeError("broken stream"), new DOMException("timeout", "AbortError")]) {
      globalThis.fetch = async () => new Response(new ReadableStream({ start(controller) { controller.error(failure); } }), {status: 200});
      await assert.rejects(new Galleton({token: "local"}).refresh("account"), error => {
        assert.ok(error instanceof GalletonError);
        assert.equal(error.code, "daemon_unavailable");
        assert.equal(error.status, 200);
        assert.match(error.message, /may already have completed/);
        return true;
      });
    }
  } finally { globalThis.fetch = originalFetch; }
});

test("response limit stops buffering while the stream is being read", async () => {
  const originalFetch = globalThis.fetch;
  let cancelled = false;
  let chunks = 0;
  try {
    globalThis.fetch = async () => new Response(new ReadableStream({
      pull(controller) { chunks++; controller.enqueue(new Uint8Array(1024 * 1024)); },
      cancel() { cancelled = true; },
    }), {status: 200});
    await assert.rejects(new Galleton({token: "local"}).status("account"), error => {
      assert.ok(error instanceof GalletonError);
      assert.equal(error.code, "invalid_response");
      assert.equal(error.status, 200);
      return true;
    });
    assert.equal(cancelled, true);
    assert.ok(chunks <= 10);
  } finally { globalThis.fetch = originalFetch; }
});

test("non-JSON HTTP errors use daemon_error", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response("upstream unavailable", {status: 503});
    await assert.rejects(new Galleton({token: "local"}).status("account"), error => {
      assert.ok(error instanceof GalletonError);
      assert.equal(error.code, "daemon_error");
      assert.equal(error.status, 503);
      return true;
    });
  } finally { globalThis.fetch = originalFetch; }
});
