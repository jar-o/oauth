# oauth2-demo-sdk

TypeScript SDK for the oauth2-demo auth server (`../src/server`) and its protected `/api`.

- **No runtime dependencies.** Uses only `fetch` and Web Crypto, so it runs in Node 20+, browsers, Deno, Bun, and edge runtimes.
- `OAuthClient` gets tokens: authorization code + PKCE, refresh, client credentials, userinfo, introspect, revoke.
- `ApiClient` gives typed methods for `/api/*`, with automatic token refresh and a retry after a 401.

```sh
cd sdk && npm install && npm run build      # → dist/
npm run example                             # client-credentials demo (needs the server on :3000)
```

To use it from another project: `npm install ../path/to/sdk`, or `npm pack` and install the tarball.

## Machine-to-machine (client credentials)

```ts
import { OAuthClient, ApiClient, ClientCredentialsTokenProvider } from "oauth2-demo-sdk";

const oauth = new OAuthClient({ issuer: "http://localhost:3000", clientId: "demo-client", clientSecret: "demo-secret" });
const api = new ApiClient({
  baseUrl: "http://localhost:3000",
  auth: new ClientCredentialsTokenProvider(oauth, "read write"), // caches the token and re-fetches before it expires
});

const { items } = await api.getData();
await api.createNote("hello");
```

## User login (authorization code + PKCE)

```ts
const oauth = new OAuthClient({ issuer: "http://localhost:3000", clientId: "demo-client", clientSecret: "demo-secret" });

// 1. /login route: build the URL, keep `request` in the user's session, redirect.
const request = await oauth.createAuthorizationRequest({
  redirectUri: "http://localhost:4000/callback",
  scope: "openid profile email read write",
});
session.oauth = request;
res.redirect(request.url);

// 2. /callback route: checks error, state and iss, then exchanges the code with the PKCE verifier.
const tokens = await oauth.handleCallback(req.url, session.oauth);

// 3. Call the API as the user. The access token is refreshed automatically when it expires.
const provider = new RefreshingTokenProvider(oauth, tokens, {
  onTokens: (t) => saveTokens(userId, t), // the server ROTATES refresh tokens, so persist each new one
});
const api = new ApiClient({ baseUrl: "http://localhost:3000", auth: provider });
const me = await api.me();
```

For public clients (SPA/native), leave out `clientSecret`. PKCE then authenticates the client, and you need to request `offline_access` to get a refresh token.

## API

### `OAuthClient`

| Member | Notes |
|---|---|
| `new OAuthClient({ issuer, clientId, clientSecret?, authMethod?, endpoints?, fetch? })` | Endpoints are derived from `issuer`. Use `endpoints` to override them, e.g. `{ token_endpoint: "http://oauth-server:3000/token" }` for in-cluster calls |
| `OAuthClient.discover(opts)` | Same, but reads endpoints from `/.well-known/oauth-authorization-server` and checks the issuer |
| `createAuthorizationRequest({ redirectUri, scope?, state?, nonce?, extraParams? })` | → `{ url, state, nonce, codeVerifier, redirectUri }` |
| `handleCallback(url, request)` | Validates `error`, `state` and `iss` (RFC 9207), then exchanges the code → `TokenSet` |
| `exchangeCode({ code, redirectUri, codeVerifier })` | Low-level exchange with no state check |
| `refresh(refreshToken, scope?)` | Rotates the refresh token. Use the new one from the result |
| `clientCredentials(scope?)` | Confidential clients only |
| `userinfo(accessToken)` / `introspect(token)` / `revoke(token)` | |

`TokenSet` is the token response plus `expiresAt` (epoch ms).

**The SDK does not verify ID token signatures.** Do that with the JWKS (`oauth.metadata.jwks_uri`) using a library such as `jose` if you rely on ID token claims, as `src/client` does.

### Token providers

| Provider | Use for |
|---|---|
| `StaticTokenProvider(token)` | A token you already have. Passing a string as `auth` uses this. Can't refresh |
| `ClientCredentialsTokenProvider(oauth, scope?)` | Service-to-service. Caches the token until 30s before expiry |
| `RefreshingTokenProvider(oauth, tokens, { onTokens? })` | User sessions. Refreshes run one at a time, so concurrent callers share a single refresh (required with rotation). `.current` gives the latest tokens |

Implement `AccessTokenProvider` (`getAccessToken(forceRefresh?)`) to plug in your own token store.

### `ApiClient`

| Method | Endpoint | Scope |
|---|---|---|
| `me()` | `GET /api/me` | any |
| `getData()` | `GET /api/data` | `read` |
| `listNotes()` | `GET /api/notes` | `read` |
| `createNote(text)` | `POST /api/notes` | `write` |
| `request<T>(method, path, body?)` | anything else | |

When a request gets a 401, a refreshing provider forces one token refresh and the request is retried once. This handles revoked tokens and server restarts.

### Errors

- `OAuthError`: `.error` (e.g. `invalid_grant`, `invalid_client`, `access_denied`, `state_mismatch`, `issuer_mismatch`, `login_required`), `.description`, `.status`.
- `ApiError`: `.status`, `.code` (`invalid_token` / `insufficient_scope`), `.missingScopes`, `.body`.

```ts
try {
  await api.createNote("x");
} catch (e) {
  if (e instanceof ApiError && e.code === "insufficient_scope") console.log("need:", e.missingScopes);
}
```
