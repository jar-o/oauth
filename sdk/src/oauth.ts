import { OAuthError } from "./errors.js";
import { createCodeChallenge, createCodeVerifier, randomString } from "./pkce.js";
import type { FetchLike, IntrospectionResponse, ServerMetadata, TokenResponse, TokenSet, UserInfo } from "./types.js";

export interface OAuthClientOptions {
  /** Issuer URL of the auth server, e.g. `http://localhost:3000`. Endpoints are derived from it. */
  issuer: string;
  clientId: string;
  /** Omit for public clients (browser/native apps); they authenticate with PKCE only. */
  clientSecret?: string;
  /** How to send the client secret to the token endpoint. Default `client_secret_basic`. */
  authMethod?: "client_secret_basic" | "client_secret_post";
  /**
   * Override individual endpoints. Useful when the server is reachable at a different
   * address than its public issuer (Docker/k8s internal networking).
   */
  endpoints?: Partial<ServerMetadata>;
  fetch?: FetchLike;
}

export interface AuthorizationRequestOptions {
  redirectUri: string;
  /** Space-delimited scopes. Default `openid profile email`. */
  scope?: string;
  state?: string;
  nonce?: string;
  /** Extra query params, e.g. `{ prompt: "consent" }`. */
  extraParams?: Record<string, string>;
}

/** Everything needed to finish the flow. Persist it (e.g. in the session) until the callback. */
export interface AuthorizationRequest {
  url: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
}

/**
 * Client for the auth server's OAuth 2.0 endpoints: authorization code + PKCE,
 * refresh, client credentials, userinfo, introspection, and revocation.
 */
export class OAuthClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly metadata: ServerMetadata;
  private readonly clientSecret?: string;
  private readonly authMethod: "client_secret_basic" | "client_secret_post";
  private readonly fetch: FetchLike;

  constructor(opts: OAuthClientOptions) {
    this.issuer = opts.issuer.replace(/\/$/, "");
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.authMethod = opts.authMethod ?? "client_secret_basic";
    this.fetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.metadata = {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/authorize`,
      token_endpoint: `${this.issuer}/token`,
      userinfo_endpoint: `${this.issuer}/userinfo`,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      introspection_endpoint: `${this.issuer}/introspect`,
      revocation_endpoint: `${this.issuer}/revoke`,
      ...opts.endpoints,
    };
  }

  /** Builds a client from the server's discovery document (RFC 8414) instead of default paths. */
  static async discover(opts: OAuthClientOptions): Promise<OAuthClient> {
    const issuer = opts.issuer.replace(/\/$/, "");
    const f = opts.fetch ?? globalThis.fetch.bind(globalThis);
    const res = await f(`${issuer}/.well-known/oauth-authorization-server`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new OAuthError("discovery_failed", `Metadata request returned ${res.status}`, res.status);
    const metadata = (await res.json()) as ServerMetadata;
    if (metadata.issuer !== issuer) throw new OAuthError("discovery_failed", `Issuer mismatch: expected ${issuer}, got ${metadata.issuer}`);
    return new OAuthClient({ ...opts, issuer, endpoints: { ...metadata, ...opts.endpoints } });
  }

  // ------------------------------------------------------------ authorization code + PKCE

  /** Step 1: create the authorize URL to send the user to, with fresh state, nonce, and PKCE verifier. */
  async createAuthorizationRequest(opts: AuthorizationRequestOptions): Promise<AuthorizationRequest> {
    const state = opts.state ?? randomString();
    const nonce = opts.nonce ?? randomString();
    const codeVerifier = createCodeVerifier();
    const url = new URL(this.metadata.authorization_endpoint);
    const params: Record<string, string> = {
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: opts.redirectUri,
      scope: opts.scope ?? "openid profile email",
      state,
      nonce,
      code_challenge: await createCodeChallenge(codeVerifier),
      code_challenge_method: "S256",
      ...opts.extraParams,
    };
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    return { url: url.toString(), state, nonce, codeVerifier, redirectUri: opts.redirectUri };
  }

  /**
   * Step 2: validate the redirect back to your app (error, state, RFC 9207 `iss`) and exchange the code.
   * `callbackUrl` is the full URL (or just its query string) your redirect URI received.
   */
  async handleCallback(callbackUrl: string | URL, request: AuthorizationRequest): Promise<TokenSet> {
    const params = new URL(callbackUrl, "http://callback.invalid").searchParams;
    const error = params.get("error");
    if (error) throw new OAuthError(error, params.get("error_description") ?? undefined);
    if (params.get("state") !== request.state) throw new OAuthError("state_mismatch", "Callback state does not match the request");
    const iss = params.get("iss");
    if (iss !== null && iss !== this.metadata.issuer) throw new OAuthError("issuer_mismatch", `Unexpected issuer ${iss}`);
    const code = params.get("code");
    if (!code) throw new OAuthError("invalid_request", "Callback has no code");
    return this.exchangeCode({ code, redirectUri: request.redirectUri, codeVerifier: request.codeVerifier });
  }

  /** Exchanges an authorization code. Prefer `handleCallback`, which also validates state. */
  exchangeCode(p: { code: string; redirectUri: string; codeVerifier: string }): Promise<TokenSet> {
    return this.tokenRequest({ grant_type: "authorization_code", code: p.code, redirect_uri: p.redirectUri, code_verifier: p.codeVerifier });
  }

  // ------------------------------------------------------------ other grants

  /**
   * Exchanges a refresh token. The server **rotates** refresh tokens: the old one is invalid
   * afterwards, so always persist the `refresh_token` from the result.
   */
  refresh(refreshToken: string, scope?: string): Promise<TokenSet> {
    return this.tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken, ...(scope ? { scope } : {}) });
  }

  /** Machine-to-machine token (confidential clients only). Default scope on the server is `read`. */
  clientCredentials(scope?: string): Promise<TokenSet> {
    return this.tokenRequest({ grant_type: "client_credentials", ...(scope ? { scope } : {}) });
  }

  // ------------------------------------------------------------ token utilities

  async userinfo(accessToken: string): Promise<UserInfo> {
    const res = await this.fetch(this.endpoint("userinfo_endpoint"), {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
    });
    if (!res.ok) throw new OAuthError(res.status === 403 ? "insufficient_scope" : "invalid_token", `userinfo returned ${res.status}`, res.status);
    return (await res.json()) as UserInfo;
  }

  /** RFC 7662. Confidential clients only. */
  async introspect(token: string): Promise<IntrospectionResponse> {
    return (await this.postForm(this.endpoint("introspection_endpoint"), { token })) as IntrospectionResponse;
  }

  /** RFC 7009. Works for refresh and access tokens; succeeds even if the token is unknown. */
  async revoke(token: string): Promise<void> {
    await this.postForm(this.endpoint("revocation_endpoint"), { token }, false);
  }

  // ------------------------------------------------------------ internals

  private async tokenRequest(params: Record<string, string>): Promise<TokenSet> {
    const body = (await this.postForm(this.metadata.token_endpoint, params)) as TokenResponse;
    return { ...body, expiresAt: body.expires_in ? Date.now() + body.expires_in * 1000 : undefined };
  }

  private async postForm(url: string, params: Record<string, string>, parseJson = true): Promise<unknown> {
    const body = new URLSearchParams(params);
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    if (this.clientSecret !== undefined && this.authMethod === "client_secret_basic") {
      headers.Authorization = `Basic ${btoa(`${encodeURIComponent(this.clientId)}:${encodeURIComponent(this.clientSecret)}`)}`;
    } else {
      body.set("client_id", this.clientId);
      if (this.clientSecret !== undefined) body.set("client_secret", this.clientSecret);
    }

    const res = await this.fetch(url, { method: "POST", headers, body });
    const json = (await res.json().catch(() => undefined)) as { error?: string; error_description?: string } | undefined;
    if (!res.ok || json?.error) {
      throw new OAuthError(json?.error ?? "server_error", json?.error_description ?? `${url} returned ${res.status}`, res.status);
    }
    return parseJson ? json : undefined;
  }

  private endpoint(key: "userinfo_endpoint" | "introspection_endpoint" | "revocation_endpoint"): string {
    const url = this.metadata[key];
    if (!url) throw new OAuthError("unsupported", `Server metadata has no ${key}`);
    return url;
  }
}
