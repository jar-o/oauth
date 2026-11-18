import { ApiError } from "./errors.js";
import { StaticTokenProvider, type AccessTokenProvider } from "./tokens.js";
import type { DataResponse, FetchLike, MeResponse, Note } from "./types.js";

export interface ApiClientOptions {
  /** Server base URL, e.g. `http://localhost:3000`. The client adds `/api/...`. */
  baseUrl: string;
  /** A raw access token, or a provider that can fetch/refresh tokens. */
  auth: string | AccessTokenProvider;
  fetch?: FetchLike;
}

/**
 * Typed client for the protected resource API (`/api/*`).
 *
 * With a refreshing provider, a 401 triggers one forced token refresh and a single retry.
 * Non-2xx responses throw `ApiError`.
 */
export class ApiClient {
  private readonly baseUrl: string;
  private readonly auth: AccessTokenProvider;
  private readonly fetch: FetchLike;

  constructor(opts: ApiClientOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/$/, "");
    this.auth = typeof opts.auth === "string" ? new StaticTokenProvider(opts.auth) : opts.auth;
    this.fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** `GET /api/me`: echoes the verified token claims. Any valid token. */
  me(): Promise<MeResponse> {
    return this.request("GET", "/api/me");
  }

  /** `GET /api/data`: requires scope `read`. */
  getData(): Promise<DataResponse> {
    return this.request("GET", "/api/data");
  }

  /** `GET /api/notes`: requires scope `read`. */
  listNotes(): Promise<Note[]> {
    return this.request("GET", "/api/notes");
  }

  /** `POST /api/notes`: requires scope `write`. Text is truncated to 500 chars by the server. */
  createNote(text: string): Promise<Note> {
    return this.request("POST", "/api/notes", { text });
  }

  /** Escape hatch for endpoints without a typed method. */
  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    let res = await this.send(method, path, body, false);
    if (res.status === 401 && !(this.auth instanceof StaticTokenProvider)) {
      res = await this.send(method, path, body, true); // token may have been revoked or the server restarted
    }
    const text = await res.text();
    let parsed: unknown = text;
    try {
      parsed = text ? JSON.parse(text) : undefined;
    } catch {}
    if (!res.ok) throw new ApiError(res.status, parsed);
    return parsed as T;
  }

  private async send(method: string, path: string, body: unknown, forceRefresh: boolean): Promise<Response> {
    const token = await this.auth.getAccessToken(forceRefresh);
    const headers: Record<string, string> = { Authorization: `Bearer ${token}`, Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return this.fetch(`${this.baseUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  }
}
