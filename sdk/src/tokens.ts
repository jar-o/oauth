import { OAuthError } from "./errors.js";
import type { OAuthClient } from "./oauth.js";
import type { TokenSet } from "./types.js";

/** Anything that can hand out a currently valid access token. */
export interface AccessTokenProvider {
  /** @param forceRefresh discard any cached token (e.g. after the API returned 401). */
  getAccessToken(forceRefresh?: boolean): Promise<string>;
}

/** Refresh this long before the server-reported expiry, to absorb clock skew and latency. */
const EXPIRY_SKEW_MS = 30_000;
const isFresh = (t?: TokenSet) => !!t && (t.expiresAt === undefined || t.expiresAt - EXPIRY_SKEW_MS > Date.now());

/** A fixed token you obtained elsewhere. Cannot refresh. */
export class StaticTokenProvider implements AccessTokenProvider {
  constructor(private readonly accessToken: string) {}
  async getAccessToken() {
    return this.accessToken;
  }
}

/**
 * Machine-to-machine: fetches tokens with the client_credentials grant and caches them
 * until shortly before expiry. Concurrent callers share a single in-flight request.
 */
export class ClientCredentialsTokenProvider implements AccessTokenProvider {
  private tokens?: TokenSet;
  private inflight?: Promise<TokenSet>;

  constructor(
    private readonly oauth: OAuthClient,
    private readonly scope?: string,
  ) {}

  async getAccessToken(forceRefresh = false): Promise<string> {
    if (!forceRefresh && isFresh(this.tokens)) return this.tokens!.access_token;
    this.inflight ??= this.oauth.clientCredentials(this.scope).finally(() => (this.inflight = undefined));
    this.tokens = await this.inflight;
    return this.tokens.access_token;
  }
}

export interface RefreshingTokenProviderOptions {
  /**
   * Called with every new token set. The server rotates refresh tokens, so persist
   * `tokens.refresh_token` here or you'll be logged out after your next restart.
   */
  onTokens?: (tokens: TokenSet) => void | Promise<void>;
}

/**
 * User tokens from the authorization-code flow. Returns the cached access token while it's
 * fresh and uses the refresh token when it isn't. Refreshes are serialized: with rotation,
 * two concurrent refreshes using the same refresh token would make the second one fail.
 */
export class RefreshingTokenProvider implements AccessTokenProvider {
  private inflight?: Promise<TokenSet>;

  constructor(
    private readonly oauth: OAuthClient,
    private tokens: TokenSet,
    private readonly opts: RefreshingTokenProviderOptions = {},
  ) {}

  /** The latest token set (including the current refresh token). */
  get current(): TokenSet {
    return this.tokens;
  }

  async getAccessToken(forceRefresh = false): Promise<string> {
    if (!forceRefresh && isFresh(this.tokens)) return this.tokens.access_token;
    this.inflight ??= this.doRefresh().finally(() => (this.inflight = undefined));
    return (await this.inflight).access_token;
  }

  private async doRefresh(): Promise<TokenSet> {
    const rt = this.tokens.refresh_token;
    if (!rt) throw new OAuthError("login_required", "Access token expired and no refresh token is available");
    const next = await this.oauth.refresh(rt);
    this.tokens = { ...next, refresh_token: next.refresh_token ?? rt };
    await this.opts.onTokens?.(this.tokens);
    return this.tokens;
  }
}
