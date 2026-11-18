import { createHash, timingSafeEqual } from "node:crypto";
import { Router, type Request, type Response } from "express";
import { config, type ClientConfig } from "./config.js";
import { authCodes, consumeAuthCode, randomToken, refreshTokens, revokedJtis } from "./store.js";
import { getJwks, signAccessToken, signIdToken, userClaims, verifyAccessToken } from "./tokens.js";
import { escapeHtml, page } from "./html.js";

export const oauthRouter = Router();

// ---------------------------------------------------------------- helpers

const findClient = (id: unknown) => config.clients.find((c) => c.clientId === id);
const findUser = (id: string) => config.users.find((u) => u.id === id);

function safeEqual(a: string, b: string) {
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

/** Authenticates the client via HTTP Basic or client_secret_post. Public clients need only client_id. */
function authenticateClient(req: Request): ClientConfig | null {
  let id: string | undefined;
  let secret: string | undefined;
  const auth = req.headers.authorization;
  if (auth?.startsWith("Basic ")) {
    const decoded = Buffer.from(auth.slice(6), "base64").toString();
    const idx = decoded.indexOf(":");
    if (idx < 0) return null;
    id = decodeURIComponent(decoded.slice(0, idx));
    secret = decodeURIComponent(decoded.slice(idx + 1));
  } else {
    id = req.body?.client_id;
    secret = req.body?.client_secret;
  }
  const client = findClient(id);
  if (!client) return null;
  if (client.clientSecret === undefined) return client; // public client
  if (typeof secret !== "string" || !safeEqual(secret, client.clientSecret)) return null;
  return client;
}

function parseScope(raw: unknown, client: ClientConfig): string[] | null {
  const requested = typeof raw === "string" && raw.trim() ? raw.trim().split(/\s+/) : ["openid"];
  const ok = requested.every((s) => config.supportedScopes.includes(s) && client.allowedScopes.includes(s));
  return ok ? [...new Set(requested)] : null;
}

function oauthError(res: Response, status: number, error: string, description?: string) {
  res.status(status).set("Cache-Control", "no-store").json({ error, error_description: description });
}

function redirectWithParams(res: Response, uri: string, params: Record<string, string | undefined>) {
  const url = new URL(uri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  res.redirect(302, url.toString());
}

// ---------------------------------------------------------------- discovery

const metadata = () => ({
  issuer: config.issuer,
  authorization_endpoint: `${config.issuer}/authorize`,
  token_endpoint: `${config.issuer}/token`,
  userinfo_endpoint: `${config.issuer}/userinfo`,
  jwks_uri: `${config.issuer}/.well-known/jwks.json`,
  introspection_endpoint: `${config.issuer}/introspect`,
  revocation_endpoint: `${config.issuer}/revoke`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
  scopes_supported: config.supportedScopes,
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256"],
});

oauthRouter.get("/.well-known/oauth-authorization-server", (_req, res) => res.json(metadata()));
oauthRouter.get("/.well-known/openid-configuration", (_req, res) => res.json(metadata()));
oauthRouter.get("/.well-known/jwks.json", (_req, res) => res.json(getJwks()));

// ---------------------------------------------------------------- /authorize

interface AuthorizeParams {
  client: ClientConfig;
  redirectUri: string;
  scope: string[];
  state?: string;
  codeChallenge: string;
  nonce?: string;
}

/**
 * Validates an authorization request. Errors about client_id / redirect_uri are rendered
 * locally (never redirect to an unverified URI); everything else is redirected back to the client.
 */
function validateAuthorize(req: Request, res: Response, src: Record<string, unknown>): AuthorizeParams | null {
  const client = findClient(src.client_id);
  const redirectUri = typeof src.redirect_uri === "string" ? src.redirect_uri : "";
  if (!client || !client.redirectUris.includes(redirectUri)) {
    res.status(400).send(page("Invalid request", `<p class="err">Unknown client_id or unregistered redirect_uri.</p>`));
    return null;
  }
  const state = typeof src.state === "string" ? src.state : undefined;
  const fail = (error: string, desc: string) => {
    redirectWithParams(res, redirectUri, { error, error_description: desc, state, iss: config.issuer });
    return null;
  };
  if (src.response_type !== "code") return fail("unsupported_response_type", "Only response_type=code is supported");
  const scope = parseScope(src.scope, client);
  if (!scope) return fail("invalid_scope", "Requested scope is not allowed");
  if (typeof src.code_challenge !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(src.code_challenge))
    return fail("invalid_request", "PKCE code_challenge (S256) is required");
  if (src.code_challenge_method !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  const nonce = typeof src.nonce === "string" ? src.nonce : undefined;
  return { client, redirectUri, scope, state, codeChallenge: src.code_challenge, nonce };
}

const AUTH_FIELDS = ["client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "nonce"];

function renderLogin(req: Request, p: AuthorizeParams, src: Record<string, unknown>, error?: string) {
  const hidden = AUTH_FIELDS.filter((f) => typeof src[f] === "string")
    .map((f) => `<input type="hidden" name="${f}" value="${escapeHtml(String(src[f]))}">`)
    .join("");
  const users = config.users.map((u) => `<code>${escapeHtml(u.username)}</code>`).join(", ");
  return page(
    "Sign in",
    `<p><strong>${escapeHtml(p.client.name)}</strong> is requesting access to:</p>
     <ul>${p.scope.map((s) => `<li><code>${escapeHtml(s)}</code></li>`).join("")}</ul>
     ${error ? `<p class="err">${escapeHtml(error)}</p>` : ""}
     <form method="post" action="/authorize">
       ${hidden}
       <label>Username <input name="username" autocomplete="username" required autofocus></label>
       <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
       <div class="row">
         <button name="decision" value="approve">Sign in &amp; approve</button>
         <button name="decision" value="deny" class="secondary" formnovalidate>Deny</button>
       </div>
     </form>
     <p class="muted">Demo users: ${users}</p>`,
  );
}

oauthRouter.get("/authorize", (req, res) => {
  const src = req.query as Record<string, unknown>;
  const p = validateAuthorize(req, res, src);
  if (p) res.set("X-Frame-Options", "DENY").send(renderLogin(req, p, src));
});

oauthRouter.post("/authorize", (req, res) => {
  const src = (req.body ?? {}) as Record<string, unknown>;
  const p = validateAuthorize(req, res, src);
  if (!p) return;

  if (src.decision !== "approve") {
    return redirectWithParams(res, p.redirectUri, { error: "access_denied", state: p.state, iss: config.issuer });
  }
  const user = config.users.find((u) => u.username === src.username);
  if (!user || typeof src.password !== "string" || !safeEqual(src.password, user.password)) {
    return res.status(401).set("X-Frame-Options", "DENY").send(renderLogin(req, p, src, "Invalid username or password"));
  }

  const code = randomToken();
  authCodes.set(code, {
    clientId: p.client.clientId,
    userId: user.id,
    redirectUri: p.redirectUri,
    scope: p.scope,
    codeChallenge: p.codeChallenge,
    nonce: p.nonce,
    expiresAt: Date.now() + config.authCodeTtlSec * 1000,
  });
  redirectWithParams(res, p.redirectUri, { code, state: p.state, iss: config.issuer });
});

// ---------------------------------------------------------------- /token

async function issueTokens(res: Response, userId: string, client: ClientConfig, scope: string[], nonce?: string) {
  const user = findUser(userId);
  if (!user) return oauthError(res, 400, "invalid_grant", "User no longer exists");
  const body: Record<string, unknown> = {
    access_token: await signAccessToken(user.id, client.clientId, scope),
    token_type: "Bearer",
    expires_in: config.accessTokenTtlSec,
    scope: scope.join(" "),
  };
  if (scope.includes("openid")) body.id_token = await signIdToken(user, client.clientId, scope, nonce);
  // Always issue a refresh token to confidential clients; public clients must ask for offline_access.
  if (client.clientSecret !== undefined || scope.includes("offline_access")) {
    const rt = randomToken();
    refreshTokens.set(rt, { clientId: client.clientId, userId, scope, expiresAt: Date.now() + config.refreshTokenTtlSec * 1000 });
    body.refresh_token = rt;
  }
  res.set("Cache-Control", "no-store").json(body);
}

oauthRouter.post("/token", async (req, res) => {
  const client = authenticateClient(req);
  if (!client) return oauthError(res, 401, "invalid_client", "Client authentication failed");
  const b = (req.body ?? {}) as Record<string, string | undefined>;

  switch (b.grant_type) {
    case "authorization_code": {
      const entry = b.code ? consumeAuthCode(b.code) : undefined;
      if (!entry || entry.clientId !== client.clientId || entry.redirectUri !== b.redirect_uri)
        return oauthError(res, 400, "invalid_grant", "Invalid, expired, or already-used code");
      if (!b.code_verifier || createHash("sha256").update(b.code_verifier).digest("base64url") !== entry.codeChallenge)
        return oauthError(res, 400, "invalid_grant", "PKCE verification failed");
      return issueTokens(res, entry.userId, client, entry.scope, entry.nonce);
    }

    case "refresh_token": {
      const entry = b.refresh_token ? refreshTokens.get(b.refresh_token) : undefined;
      if (!entry || entry.clientId !== client.clientId || entry.expiresAt < Date.now())
        return oauthError(res, 400, "invalid_grant", "Invalid or expired refresh token");
      refreshTokens.delete(b.refresh_token!); // rotate
      let scope = entry.scope;
      if (b.scope) {
        const narrowed = b.scope.split(/\s+/);
        if (!narrowed.every((s) => entry.scope.includes(s))) return oauthError(res, 400, "invalid_scope");
        scope = narrowed;
      }
      return issueTokens(res, entry.userId, client, scope);
    }

    case "client_credentials": {
      if (client.clientSecret === undefined) return oauthError(res, 401, "unauthorized_client", "Public clients cannot use client_credentials");
      const scope = parseScope(b.scope ?? "read", client)?.filter((s) => !["openid", "profile", "email", "offline_access"].includes(s));
      if (!scope) return oauthError(res, 400, "invalid_scope");
      return res.set("Cache-Control", "no-store").json({
        access_token: await signAccessToken(client.clientId, client.clientId, scope),
        token_type: "Bearer",
        expires_in: config.accessTokenTtlSec,
        scope: scope.join(" "),
      });
    }

    default:
      return oauthError(res, 400, "unsupported_grant_type");
  }
});

// ---------------------------------------------------------------- /userinfo

oauthRouter.get("/userinfo", async (req, res) => {
  const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
  const claims = token ? await verifyAccessToken(token) : null;
  if (!claims) return res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').end();
  const user = findUser(claims.sub);
  if (!user || !claims.scope.split(" ").includes("openid"))
    return res.status(403).set("WWW-Authenticate", 'Bearer error="insufficient_scope"').end();
  res.json(userClaims(user, claims.scope.split(" ")));
});

// ---------------------------------------------------------------- /introspect (RFC 7662)

oauthRouter.post("/introspect", async (req, res) => {
  const client = authenticateClient(req);
  if (!client || client.clientSecret === undefined) return oauthError(res, 401, "invalid_client");
  const token = req.body?.token as string | undefined;
  if (!token) return res.json({ active: false });

  const rt = refreshTokens.get(token);
  if (rt && rt.expiresAt > Date.now()) {
    return res.json({ active: true, token_type: "refresh_token", client_id: rt.clientId, sub: rt.userId, scope: rt.scope.join(" "), exp: Math.floor(rt.expiresAt / 1000) });
  }
  const claims = await verifyAccessToken(token);
  if (!claims) return res.json({ active: false });
  res.json({ active: true, token_type: "access_token", ...claims });
});

// ---------------------------------------------------------------- /revoke (RFC 7009)

oauthRouter.post("/revoke", async (req, res) => {
  const client = authenticateClient(req);
  if (!client) return oauthError(res, 401, "invalid_client");
  const token = req.body?.token as string | undefined;
  if (token) {
    const rt = refreshTokens.get(token);
    if (rt?.clientId === client.clientId) refreshTokens.delete(token);
    const claims = await verifyAccessToken(token);
    if (claims?.client_id === client.clientId && claims.exp) revokedJtis.set(claims.jti, claims.exp * 1000);
  }
  res.status(200).end(); // always 200 per spec, even for unknown tokens
});
