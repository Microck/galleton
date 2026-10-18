import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { json } from "node:stream/consumers";
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

// Exercise actual HTTP responses instead of replacing the SDK's fetch implementation.
async function withDaemon(handler, run) {
  const server = createServer(handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const client = new Galleton({token: "local", baseURL: `http://127.0.0.1:${server.address().port}`});
  try { await run(client); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test("body-read failures preserve status and uncertain completion", async () => {
  await withDaemon((_request, response) => {
    response.writeHead(200, {"Content-Length": "100"});
    response.write("{");
    // The headers reach the real client before the stream is interrupted.
    setImmediate(() => response.destroy());
  }, client => assert.rejects(client.refresh("account"), error => {
    assert.ok(error instanceof GalletonError);
    assert.equal(error.code, "daemon_unavailable");
    assert.equal(error.status, 200);
    assert.match(error.message, /may already have completed/);
    return true;
  }));
});

test("response limit cancels an HTTP stream before it finishes", {timeout: 15000}, async () => {
  let chunks = 0;
  let closed;
  await withDaemon((_request, response) => {
    closed = once(response, "close");
    response.writeHead(200);
    const chunk = Buffer.alloc(1024 * 1024);
    function sendChunk() {
      if (response.destroyed) return;
      if (chunks === 160) { response.end(); return; }
      chunks++;
      response.write(chunk, () => setImmediate(sendChunk));
    }
    sendChunk();
  }, async client => {
    await assert.rejects(client.status("account"), error => {
      assert.ok(error instanceof GalletonError);
      assert.equal(error.code, "invalid_response");
      assert.equal(error.status, 200);
      return true;
    });
    await closed;
    assert.ok(chunks < 160, "the client must cancel before the whole response is sent");
  });
});

test("non-JSON HTTP errors use daemon_error", async () => {
  await withDaemon((_request, response) => {
    response.writeHead(503);
    response.end("upstream unavailable");
  }, client => assert.rejects(client.status("account"), error => {
    assert.ok(error instanceof GalletonError);
    assert.equal(error.code, "daemon_error");
    assert.equal(error.status, 503);
    return true;
  }));
});

test("JSON requests replace case-variant content-type headers", async () => {
  let sent;
  await withDaemon(async (request, response) => {
    sent = await json(request);
    response.writeHead(200, {"Content-Type": "application/json"});
    response.end(JSON.stringify({status: 200, headers: {}, body_base64: "", revision: 1}));
  }, client => client.request("account", "https://example.test/data", {
    headers: {"content-type": "text/plain", "X-Test": "ok"},
    json: {ok: true},
  }));
  assert.deepEqual(sent.headers, {"X-Test": "ok", "Content-Type": "application/json"});
});

test("provider pause, resume and list use the documented routes", async () => {
  const seen = [];
  await withDaemon(async (request, response) => {
    const body = request.method === "POST" ? await json(request) : undefined;
    seen.push([request.method, request.url, body]);
    response.writeHead(200, {"Content-Type": "application/json"});
    if (request.url === "/v1/providers") response.end(JSON.stringify({providers: [{name: "x", kind: "k", origins: [], proxied: false}]}));
    else response.end(JSON.stringify({provider: "x", paused_until: "2026-01-01T00:00:00Z"}));
  }, async client => {
    assert.equal((await client.providers())[0].name, "x");
    assert.equal((await client.pause("x", 60)).provider, "x");
    await client.resume("x");
  });
  assert.deepEqual(seen, [
    ["GET", "/v1/providers", undefined],
    ["POST", "/v1/providers/x/pause", {seconds: 60}],
    ["DELETE", "/v1/providers/x/pause", undefined],
  ]);
});

test("invalid provider names and seconds throw without a network request", () => {
  const c = new Galleton({token: "local", baseURL: "http://127.0.0.1:1"});
  assert.throws(() => c.pause("../x", 60), TypeError);
  assert.throws(() => c.resume("a/b"), TypeError);
  for (const s of [0, 86401, 1.5, NaN]) assert.throws(() => c.pause("x", s), TypeError);
});
