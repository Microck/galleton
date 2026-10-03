export class GalletonError extends Error {
    code;
    status;
    retryAt;
    constructor(code, message, status = 0, retryAt) {
        super(message);
        this.code = code;
        this.status = status;
        this.retryAt = retryAt;
        this.name = "GalletonError";
    }
}
export class ManagedResponse {
    status;
    headers;
    body;
    revision;
    constructor(status, headers, body, revision) {
        this.status = status;
        this.headers = headers;
        this.body = body;
        this.revision = revision;
    }
    get ok() { return this.status >= 200 && this.status < 300; }
    text() { return new TextDecoder().decode(this.body); }
    json() { return JSON.parse(this.text()); }
}
function encode64(bytes) {
    let binary = "";
    for (let start = 0; start < bytes.length; start += 8192) {
        binary += String.fromCharCode(...bytes.subarray(start, start + 8192));
    }
    return btoa(binary);
}
function decode64(value) {
    return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}
function sessionPath(id) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(id))
        throw new TypeError("Invalid session ID");
    return `/v1/sessions/${id}`;
}
async function responseText(response) {
    const reader = response.body?.getReader();
    if (!reader)
        return "";
    const decoder = new TextDecoder();
    let size = 0;
    let text = "";
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            size += value.byteLength;
            if (size > 8 * 1024 * 1024) {
                await reader.cancel().catch(() => { });
                throw new GalletonError("invalid_response", "Oversized daemon response.", response.status);
            }
            text += decoder.decode(value, { stream: true });
        }
        return text + decoder.decode();
    }
    finally {
        reader.releaseLock();
    }
}
export class Galleton {
    base;
    token;
    timeoutMs;
    constructor(options) {
        const url = new URL(options.baseURL ?? "http://127.0.0.1:8766");
        const host = url.hostname;
        const loopback = host === "[::1]" ||
            /^127(?:\.[0-9]{1,3}){3}$/.test(host) && host.split(".").every(n => +n <= 255);
        if (!loopback || url.protocol !== "http:" || url.username || url.password ||
            url.search || url.hash || url.pathname !== "/") {
            throw new TypeError("Galleton requires a literal loopback HTTP origin");
        }
        this.base = url.origin;
        this.token = options.token.trim();
        if (!this.token || /[\r\n]/.test(this.token))
            throw new TypeError("Invalid local API token");
        this.timeoutMs = options.timeoutMs ?? 300_000;
        if (!Number.isFinite(this.timeoutMs) || this.timeoutMs <= 0)
            throw new TypeError("Invalid timeout");
    }
    async call(method, path, body) {
        let response;
        try {
            response = await fetch(this.base + path, {
                method,
                headers: { Authorization: `Bearer ${this.token}`, "Content-Type": "application/json" },
                body: body === undefined ? undefined : JSON.stringify(body),
                redirect: "manual", signal: AbortSignal.timeout(this.timeoutMs),
            });
        }
        catch {
            throw new GalletonError("daemon_unavailable", "Galleton is unavailable or the local request timed out.");
        }
        let text;
        try {
            text = await responseText(response);
        }
        catch (error) {
            if (error instanceof GalletonError)
                throw error;
            throw new GalletonError("daemon_unavailable", "Galleton response was interrupted; the request may already have completed.", response.status);
        }
        let decoded;
        try {
            decoded = JSON.parse(text);
        }
        catch {
            if (!response.ok)
                throw new GalletonError("daemon_error", "Galleton request failed.", response.status);
            throw new GalletonError("invalid_response", "Expected a JSON daemon response.", response.status);
        }
        if (!response.ok) {
            const error = decoded.error;
            throw new GalletonError(error?.code ?? "daemon_error", error?.message ?? "Galleton request failed.", response.status, error?.retry_at);
        }
        return decoded;
    }
    connect(id, credentials) {
        return this.call("PUT", sessionPath(id), credentials);
    }
    status(id) { return this.call("GET", sessionPath(id)); }
    async list() {
        return (await this.call("GET", "/v1/sessions")).sessions;
    }
    refresh(id) { return this.call("POST", sessionPath(id) + "/refresh", {}); }
    async headers(id, url) {
        return (await this.call("POST", sessionPath(id) + "/headers", { url })).headers;
    }
    capture(id, url, setCookie) {
        return this.call("POST", sessionPath(id) + "/cookies", { url, set_cookie: setCookie });
    }
    async forget(id) { await this.call("DELETE", sessionPath(id)); }
    /** Buffered request with automatic Cookie/Authorization injection and Set-Cookie capture.
     *  Resource calls are never automatically retried. Non-2xx upstream statuses are returned. */
    async request(id, url, options = {}) {
        if (options.body !== undefined && options.json !== undefined)
            throw new TypeError("Use body or json, not both");
        const headers = { ...options.headers };
        let body = options.body;
        if (options.json !== undefined) {
            body = JSON.stringify(options.json);
            for (const name of Object.keys(headers)) {
                if (name.toLowerCase() === "content-type")
                    delete headers[name];
            }
            headers["Content-Type"] = "application/json";
        }
        const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body ?? new Uint8Array();
        if (bytes.length > 1024 * 1024)
            throw new TypeError("Request body exceeds 1 MiB");
        const wire = await this.call("POST", sessionPath(id) + "/request", {
            url, method: options.method ?? "GET", headers, body_base64: encode64(bytes),
        });
        return new ManagedResponse(wire.status, wire.headers, decode64(wire.body_base64), wire.revision);
    }
}
