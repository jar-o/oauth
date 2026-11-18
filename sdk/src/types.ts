// Wire types. Keep in sync with src/server (oauth.ts, tokens.ts, api.ts).

export type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** RFC 8414 authorization server metadata (the subset this SDK uses). */
export interface ServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  scopes_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  [key: string]: unknown;
}

/** Raw /token response. */
export interface TokenResponse {
  access_token: string;
  token_type: "Bearer" | string;
  expires_in?: number;
  scope?: string;
  refresh_token?: string;
  id_token?: string;
}

/** Token response plus an absolute expiry, as returned by every SDK grant method. */
export interface TokenSet extends TokenResponse {
  /** Epoch milliseconds when the access token expires, if the server said. */
  expiresAt?: number;
}

export interface AccessTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  client_id: string;
  scope: string;
  jti: string;
  iat: number;
  exp: number;
}

export interface UserInfo {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  [claim: string]: unknown;
}

export type IntrospectionResponse =
  | { active: false }
  | ({ active: true; token_type: "access_token" } & AccessTokenClaims)
  | { active: true; token_type: "refresh_token"; client_id: string; sub: string; scope: string; exp: number };

// ---------------------------------------------------------------- /api resources

export interface MeResponse {
  message: string;
  token: AccessTokenClaims;
}

export interface Item {
  id: number;
  name: string;
  qty: number;
}

export interface DataResponse {
  owner: string;
  items: Item[];
}

export interface Note {
  by: string;
  text: string;
  at: string;
}
