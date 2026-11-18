# AGENTS.md

Guide for coding agents (and humans) working in this repo. The README covers how to *use* the apps; this explains how the code *works*.

## Overview

One TypeScript package, two independent Express 5 apps that share nothing at runtime:

| App | Entry | Port | Role |
|---|---|---|---|
| Auth server | `src/server/index.ts` | 3000 | OAuth 2.0 authorization server + OIDC bits + a protected resource API (`/api`) |
| Test client | `src/client/index.ts` | 4000 | OAuth/OIDC relying party with an authed `/profile` page; talks to the local server **and/or Google** |
| SDK | `sdk/src/index.ts` | — | Separate package (`sdk/package.json`) for calling the server and `/api` from TypeScript |

The client treats the local server as just another external provider. Don't import across `src/server` ↔ `src/client`: they're meant to be deployable and replaceable independently.

## Commands

```sh
npm run dev:server     # tsx watch, port 3000
npm run dev:client     # tsx watch, port 4000 (loads .env; restart after editing .env)
npm run build          # tsc → dist/
npm run typecheck
docker compose up --build
```

There is no automated test suite. Verify changes by running both apps and driving the flow with `curl` and a cookie jar (see [Verifying changes](#verifying-changes)).

## Conventions

- ESM (`"type": "module"`, `NodeNext`): relative imports **must** use the `.js` extension (`import { config } from "./config.js"`).
- Server runtime deps are `express`, `jose`, and `@harperfast/rocksdb-js` (prebuilt native binaries, no compiler needed). Prefer `node:crypto` and `fetch` over adding packages.
- All configuration comes from env vars, read once at startup. There's no config file.
- HTML is rendered from template strings. **Always** pass interpolated values through `escapeHtml` (server) / `esc` (client).
- **Server** state is persisted in an embedded RocksDB directory (`DATA_DIR`, default `./data`, git-ignored). **Client** sessions are still in-memory `Map`s. RocksDB allows one process per data directory, so the server is single-replica by design (k8s: `replicas: 1` + `Recreate`).

---

## Auth server (`src/server`)

### Files

| File | Responsibility |
|---|---|
| `index.ts` | Boot: `openDb()`, `await initKeys()`, body parsers, mounts `oauthRouter` at `/` and `apiRouter` at `/api`, `/healthz`, 60s `sweepExpired` timer, graceful shutdown (closes the HTTP server, then the DB) |
| `config.ts` | Env parsing. Clients and users default to a demo client and alice/bob; `CLIENTS_JSON` / `USERS_JSON` replace them wholesale |
| `db.ts` | Opens/closes RocksDB and defines `Collection<T>`: a typed wrapper around one column family (`get`/`has`/`put`/`delete`/`take`/`entries`/`deleteWhere`). All calls are **synchronous** |
| `store.ts` | The collections (`auth_codes`, `refresh_tokens`, `revoked_jtis`, `notes`, `meta`) and the domain helpers: `consumeAuthCode()`, `getRefreshToken()`, `isJtiRevoked()`, `addNote()`/`listNotes()`, `sweepExpired()`, `randomToken()` |
| `tokens.ts` | RSA key management, JWT signing/verification, JWKS, OIDC user claims |
| `oauth.ts` | All protocol endpoints (discovery, `/authorize`, `/token`, `/userinfo`, `/introspect`, `/revoke`) |
| `api.ts` | `requireAuth(...scopes)` bearer middleware + example resource endpoints |
| `html.ts` | `escapeHtml` and the `page()` layout for the login screen |

### Datastore (`db.ts`, `store.ts`)

- One RocksDB database at `DATA_DIR` (created with mode `0700`, because it holds refresh tokens and possibly the signing key). Each collection is a column family, opened lazily by `db.use(name)`. Values are plain objects, serialized by the library with msgpack.
- **Everything is sync on purpose.** Node runs each sync call to completion, so read-validate-delete sequences (`take()` for codes, get → check → delete for refresh rotation in `/token`) can't interleave between requests. Don't put an `await` between reading a single-use record and deleting it.
- Expiry: every record has an absolute `expiresAt` (ms). Reads ignore expired records (`live()`), and `sweepExpired()` deletes them every 60s with a full scan, which is fine at this scale.
- Note keys are a zero-padded timestamp plus a random suffix, so `entries()` (a key-ordered range scan) returns them in creation order. Use the same trick for any other ordered collection.
- To add a collection: `export const things = new Collection<Thing>("things")` in `store.ts`. If the records expire, add it to `sweepExpired()`.
- Only one process can open `DATA_DIR`. A second one fails at startup with `ERR_DATABASE_LOCKED`. When testing, give your copy its own `DATA_DIR`.

### Keys and tokens

- `initKeys()` picks the signing key in this order: `SIGNING_KEY_PEM` env → the key stored in the `meta` collection → generate a 2048-bit RSA key and store it in `meta`. So by default the key (and every token signed with it) survives restarts, as long as `DATA_DIR` does. It derives the public key and a `kid` (truncated SHA-256 of the JWK's `e`/`kty`/`n`).
- **Access tokens** are RS256 JWTs with header `typ: at+jwt`. Claims: `iss` = `aud` = `config.issuer` (the server is its own resource server), `sub` (user id, or client id for `client_credentials`), `client_id`, space-delimited `scope`, random `jti`, and `exp` = `ACCESS_TOKEN_TTL`.
- **ID tokens** are RS256 JWTs with `typ: JWT`, `aud` = client id, an optional `nonce`, and profile/email claims gated by scope via `userClaims()`.
- **Refresh tokens** are *opaque* random strings stored in `refreshTokens`, not JWTs.
- `verifyAccessToken()` is the single validation path, used by `/userinfo`, `/introspect`, `/revoke`, and `requireAuth`. It checks signature, `iss`, `aud`, `typ`, and `alg`, then rejects any `jti` in `revokedJtis`. It returns `null` on any failure and never throws.

### Endpoints (`oauth.ts`)

**Client authentication.** `authenticateClient(req)` accepts HTTP Basic (URL-decoded per RFC 6749 §2.3.1) or `client_id`/`client_secret` in the form body. A client without `clientSecret` is *public* and authenticates with `client_id` alone. Secrets and passwords are compared with `safeEqual`, which SHA-256s both sides and then uses `timingSafeEqual`, so length differences don't leak.

**`GET/POST /authorize`.** Both methods go through `validateAuthorize()`:
1. Unknown `client_id`, or a `redirect_uri` not in the client's list (**exact string match**), gets a local 400 page. The server never redirects to an unverified URI.
2. Any other error redirects back to the client with `error`, `state`, and `iss` (RFC 9207).
3. Requirements: `response_type=code`, scopes that are both globally supported and allowed for this client (default `openid`), and **PKCE is mandatory**: a 43-char base64url `code_challenge` with `code_challenge_method=S256`.

`GET` renders a combined login + consent form. The original query parameters are carried in hidden inputs (whitelisted by `AUTH_FIELDS`). `POST` re-validates everything, handles Deny (`access_denied`), checks credentials, stores an `AuthCode` (60s TTL), and redirects with `code`, `state`, and `iss`. Both responses send `X-Frame-Options: DENY`.

**`POST /token`.** The client is authenticated first, then the handler switches on `grant_type`:
- `authorization_code`: `consumeAuthCode()` deletes the code *before* checking it, so codes are single-use even when the exchange fails. It then checks that `client_id` and `redirect_uri` match the stored values and that `SHA256(code_verifier)` equals the stored challenge, and calls `issueTokens()`.
- `refresh_token`: checks the token exists, belongs to this client, and hasn't expired. The old token is **deleted (rotation)**. The request may narrow the scope but not widen it.
- `client_credentials`: confidential clients only. User-only scopes (`openid`, `profile`, `email`, `offline_access`) are stripped, and the default scope is `read`.

`issueTokens()` always returns an access token. It adds an ID token if `openid` is in scope, and a refresh token for confidential clients, or for public clients that requested `offline_access`. Responses set `Cache-Control: no-store`.

**`/userinfo`** needs a valid access token with `openid` in scope, plus a `sub` that resolves to a user (so `client_credentials` tokens get 403).
**`/introspect`** (RFC 7662) is for confidential clients only. It checks refresh tokens first, then access JWTs.
**`/revoke`** (RFC 7009) always returns 200. A refresh token is deleted. For an access token, its `jti` goes into `revokedJtis` until its original `exp`. Revocation only applies to tokens owned by the calling client.

Discovery metadata is generated from `config.issuer` and served at both `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`. JWKS is served at `/.well-known/jwks.json`.

### Resource API (`api.ts`)

`requireAuth(...scopes)` parses `Authorization: Bearer`, verifies the token, and enforces **all** listed scopes. A bad token gets 401; a missing scope gets 403 with `insufficient_scope` and a `WWW-Authenticate` header. On success it sets `req.auth` to the token claims (typed through module augmentation of `express-serve-static-core`).

| Route | Scope |
|---|---|
| `GET /api/me` | any valid token |
| `GET /api/data`, `GET /api/notes` | `read` |
| `POST /api/notes` | `write` |

To add a protected route, add `apiRouter.get("/x", requireAuth("scope"), handler)`. To add a new scope, also add it to `config.supportedScopes` and to the client's `allowedScopes`.

---

## Test client (`src/client/index.ts`)

It's a single file, organized into sections: providers, sessions, HTTP helpers, HTML, routes.

### Providers

`Provider` describes one OAuth/OIDC provider: endpoints, client credentials, scopes, the expected `issuer` (a string or an array, since Google uses two forms), a `jose` remote JWKS set, `extraAuthParams`, and `revokeWithClientAuth`. `addProvider()` registers it in the `providers` map.

- **`local`** is always registered. Browser-facing URLs (`/authorize`) use `AUTH_SERVER_PUBLIC_URL`; server-to-server calls (token, userinfo, revoke, JWKS, API) use `AUTH_SERVER_INTERNAL_URL`. The two differ inside Docker and k8s. The expected `iss` is the *public* URL, because that's what the server stamps into tokens.
- **`google`** is registered only if `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set. Its endpoints are hardcoded from Google's discovery doc. It sends `access_type=offline` + `prompt=consent` so Google returns a refresh token. It revokes with only the token (`revokeWithClientAuth: false`). It has no API call unless `GOOGLE_API_URL` is set.

To add a provider, add another `addProvider({...})` block. The routes are provider-agnostic.

`process.loadEnvFile(".env")` runs at import time, wrapped in try/catch, so `.env` is optional.

### Sessions

`sessions: Map<sid, Session>` is keyed by an `sid` cookie (HttpOnly, SameSite=Lax, and Secure when `BASE_URL` is https). `session(req, res)` gets or creates the session and sets the cookie. Tokens **never** reach the browser.

```ts
Session {
  pending?   // one in-flight login: provider, state, PKCE verifier, nonce, returnTo
  provider?  // which provider the current tokens came from
  tokens?    // access/refresh/id token + expires_at
  idClaims?  // verified ID token payload
  user?      // userinfo response (falls back to idClaims)
}
```

### Flow

1. **`GET /`** shows a "Log in with X" button for each provider (`/login?provider=…&returnTo=…`) and that provider's config.
2. **`GET /login`** creates a fresh `state`, PKCE `verifier` (48 bytes), and `nonce`, stores them in `s.pending`, and redirects to the provider's authorize URL with an S256 `code_challenge`.
3. **`GET /callback`** (one redirect URI shared by every provider: `$BASE_URL/callback`):
   - takes `s.pending` and clears it at once, so it can only be used once;
   - surfaces `error`, then requires `state` to match `pending.state`;
   - if `iss` is present, it must match the provider's issuer (RFC 9207 mix-up defence; the local server sends `iss`);
   - exchanges the code with `client_secret_post` and the `code_verifier`;
   - `verifyIdToken()`: signature checked against the provider's JWKS, plus `iss`, `aud` = client id, `exp`, and `nonce`;
   - **only after everything succeeds** does it replace `s.provider` / `s.tokens`, so a failed login with one provider doesn't log you out of another;
   - fetches userinfo, then redirects to `pending.returnTo`.
4. **`GET /profile`** (behind `requireLogin`) calls the provider's `apiUrl` live on each load and renders user info, the verified ID token claims, and the access token (decoded if it's a JWT; Google's are opaque).
5. **`POST /refresh`** runs the refresh grant. A new ID token, if returned, is verified without a nonce. `storeTokens()` keeps the old refresh token if the provider doesn't rotate (Google doesn't).
6. **`POST /logout`** revokes the refresh and access tokens with the provider (best effort), then clears the session fields.

`returnTo` is restricted to same-origin paths by `safeReturnTo()` (it must start with `/` and not `//`) to prevent open redirects.

---

## SDK (`sdk/`)

`sdk/` is a standalone npm package with its own `package.json`, `tsconfig.json`, and `node_modules`. It is **not** part of the root build or the Docker image. It has zero runtime dependencies (only `fetch` + Web Crypto), so don't add `node:` imports or packages to `sdk/src`. Build it with `cd sdk && npm run build`.

| File | Responsibility |
|---|---|
| `oauth.ts` | `OAuthClient`: endpoints come from `issuer` (or `discover()`). Has the PKCE request builder, `handleCallback` (checks error/state/iss, then the code exchange), the grants, userinfo/introspect/revoke. Client auth is Basic by default, or `client_secret_post` |
| `tokens.ts` | `AccessTokenProvider` interface + Static / ClientCredentials / Refreshing providers. Tokens count as stale 30s before `expiresAt`. In-flight requests are shared through an `inflight` promise, so concurrent refreshes never spend a rotated refresh token twice |
| `api.ts` | `ApiClient`: typed `/api` methods + `request<T>()`. On a 401 with a non-static provider: one forced refresh and one retry |
| `errors.ts` | `OAuthError` (protocol errors), `ApiError` (non-2xx from `/api`, exposes `code` + `missingScopes`) |
| `types.ts` | Wire types. **Hand-maintained mirror of the server's responses.** When you change a response shape, scope, or route in `src/server`, update `sdk/src/types.ts` and add or adjust the method in `sdk/src/api.ts` |

The SDK does not verify ID token signatures (it would need `jose`). The test client does.

## Deployment files

- `Dockerfile`: multi-stage, one image. The default `CMD` runs the server; override it with `node dist/client/index.js` for the client. It runs as `node` (uid 1000). `DATA_DIR=/data` is declared as a `VOLUME`.
- `docker-compose.yml`: the client reaches the server at `http://oauth-server:3000` internally, and at `localhost:3000` from the browser. The server's RocksDB lives in the named volume `oauth-data`. Google credentials are passed in from the host env or `.env`.
- `k8s/oauth.yaml`: a namespace, Secret, and Deployment + Service for each app, plus a 1Gi PVC mounted at `/data` for the server. The server Deployment uses `strategy: Recreate`, because a rolling update would start the new pod while the old one still holds the RocksDB lock. The URLs assume `kubectl port-forward`. Optional Secret keys: `signing-key.pem`, `google-client-id`, and `google-client-secret`.

If you change an env var name, update `config.ts` or the client, plus `docker-compose.yml`, `k8s/oauth.yaml`, `.env.example`, and the README.

## Gotchas

- **Redirect URIs are exact-match.** The client always sends `$BASE_URL/callback`. The local server's `DEMO_CLIENT_REDIRECT_URIS` and Google's "Authorized redirect URIs" must contain that exact string. Google's `redirect_uri_mismatch` almost always means a console misconfiguration, such as the URI being entered under *JavaScript origins*.
- **`ISSUER` must equal the client's `AUTH_SERVER_PUBLIC_URL`**, or ID token and `iss` checks fail.
- `tsx watch` doesn't reload `.env`, so restart the client after editing it.
- Server state persists in `DATA_DIR` (delete the directory to reset everything). Client sessions are in memory, so restarting the client logs users out of the test app, but their server-side tokens stay valid.
- `ERR_DATABASE_LOCKED` at startup means another server process (often the user's own `npm run dev:server`) already has that `DATA_DIR` open.
- Ports 3000 and 4000 may already be taken by the user's own dev processes. When testing, run your copies on other ports (see below) rather than killing theirs.

## Verifying changes

```sh
npm run build
DATA_DIR=$(mktemp -d) PORT=3100 ISSUER=http://localhost:3100 DEMO_CLIENT_REDIRECT_URIS=http://localhost:4100/callback node dist/server/index.js &
PORT=4100 BASE_URL=http://localhost:4100 AUTH_SERVER_PUBLIC_URL=http://localhost:3100 node dist/client/index.js &
```

Then use `curl -c jar -b jar`:
1. `GET :4100/login?provider=local` and capture the authorize URL.
2. POST its query params plus `username=alice&password=password&decision=approve` to `:3100/authorize`.
3. Follow the returned callback URL with the cookie jar.
4. `GET :4100/profile` should show "Hello, Alice Example" and an API status of 200.

For the SDK, `cd sdk && ISSUER=http://localhost:3100 npm run example` exercises client credentials, the typed API, and scope errors.

For Google without real credentials, set fake `GOOGLE_CLIENT_*` values and check the parameters in the `/login?provider=google` redirect URL.
