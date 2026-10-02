/** Server-side client for an authenticated, loopback-only Galleton daemon. */
export interface Credentials {
    provider: string;
    cookie_origin?: string;
    cookie_header?: string;
    set_cookies?: string[];
    access_token?: string;
    refresh_token?: string;
    access_expires_at?: string;
    secrets?: Record<string, string>;
    replace?: boolean;
    expected_revision?: number;
}
export interface Problem {
    code: string;
    message: string;
    retry_at?: string;
}
export interface SessionStatus {
    id: string;
    provider: string;
    status: string;
    revision: number;
    created_at: string;
    last_refresh?: string;
    next_refresh?: string;
    access_expires_at?: string;
    cookie_count: number;
    error?: Problem;
}
export declare class GalletonError extends Error {
    readonly code: string;
    readonly status: number;
    readonly retryAt?: string | undefined;
    constructor(code: string, message: string, status?: number, retryAt?: string | undefined);
}
export interface RequestOptions {
    method?: string;
    headers?: Record<string, string>;
    body?: Uint8Array | string;
    json?: unknown;
}
export declare class ManagedResponse {
    readonly status: number;
    readonly headers: Record<string, string[]>;
    readonly body: Uint8Array;
    readonly revision: number;
    constructor(status: number, headers: Record<string, string[]>, body: Uint8Array, revision: number);
    get ok(): boolean;
    text(): string;
    json<T = unknown>(): T;
}
export declare class Galleton {
    private readonly base;
    private readonly token;
    private readonly timeoutMs;
    constructor(options: {
        token: string;
        baseURL?: string;
        timeoutMs?: number;
    });
    private call;
    connect(id: string, credentials: Credentials): Promise<SessionStatus>;
    status(id: string): Promise<SessionStatus>;
    list(): Promise<SessionStatus[]>;
    refresh(id: string): Promise<SessionStatus>;
    headers(id: string, url: string): Promise<Record<string, string>>;
    capture(id: string, url: string, setCookie: string[]): Promise<SessionStatus>;
    forget(id: string): Promise<void>;
    /** Buffered request with automatic Cookie/Authorization injection and Set-Cookie capture.
     *  Resource calls are never automatically retried. Non-2xx upstream statuses are returned. */
    request(id: string, url: string, options?: RequestOptions): Promise<ManagedResponse>;
}
