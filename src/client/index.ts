/**
 * Minimal OAuth2 / OIDC relying-party web app for manually testing providers.
 * Runs the authorization-code + PKCE flow, keeps tokens server-side in a session,
 * and exposes an authed /profile page that calls userinfo and (optionally) a protected API.
 *
 * Providers:
 *   - "local":  the bundled auth server (`npm run dev:server`) — always enabled
 *   - "google": enabled when GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set
 */
import express, { type Request, type Response, type NextFunction } from "express";
import { createHash, randomBytes } from "node:crypto";
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from "jose";

try {
  process.loadEnvFile(".env"); // optional local .env (never committed)
} catch {}

const env = (k: string, d?: string) => process.env[k] ?? d;

// ---------------------------------------------------------------- providers

interface Provider {
  id: string;
  name: string;
  clientId: string;
  clientSecret?: string;
  scopes: string;
  authorizeUrl: string;
  tokenUrl: string;
  userinfoUrl?: string;
  revokeUrl?: string;
  /** Protected resource to call with the access token on /profile. */
  apiUrl?: string;
  /** Expected `iss` of ID tokens (and of the RFC 9207 `iss` callback param, if sent). */
  issuer: string | string[];
  jwks: ReturnType<typeof createRemoteJWKSet>;
  jwksUrl: string;
  extraAuthParams?: Record<string, string>;
  /** Whether the revocation endpoint expects client credentials (RFC 7009) or just the token (Google). */
  revokeWithClientAuth: boolean;
}

const trim = (u: string) => u.replace(/\/$/, "");
/** Browser-facing URL of the local auth server (the /authorize redirect + `iss`). */
const LOCAL_PUBLIC = trim(env("AUTH_SERVER_PUBLIC_URL", "http://localhost:3000")!);
/** Server-to-server URL of the local auth server. Differs inside Docker/k8s. */
const LOCAL_INTERNAL = trim(env("AUTH_SERVER_INTERNAL_URL", LOCAL_PUBLIC)!);

const providers = new Map<string, Provider>();
function addProvider(p: Omit<Provider, "jwks">) {
  providers.set(p.id, { ...p, jwks: createRemoteJWKSet(new URL(p.jwksUrl)) });
}

addProvider({
  id: "local",
  name: "Local OAuth2 Server",
  clientId: env("LOCAL_CLIENT_ID", "demo-client")!,
  clientSecret: env("LOCAL_CLIENT_SECRET", "demo-secret"),
  scopes: env("LOCAL_SCOPES", "openid profile email read write")!,
  authorizeUrl: `${LOCAL_PUBLIC}/authorize`,
  tokenUrl: `${LOCAL_INTERNAL}/token`,
  userinfoUrl: `${LOCAL_INTERNAL}/userinfo`,
  revokeUrl: `${LOCAL_INTERNAL}/revoke`,
  apiUrl: `${LOCAL_INTERNAL}/api/data`,
  issuer: LOCAL_PUBLIC,
  jwksUrl: `${LOCAL_INTERNAL}/.well-known/jwks.json`,
  revokeWithClientAuth: true,
});

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  addProvider({
    id: "google",
    name: "Google",
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    scopes: env("GOOGLE_SCOPES", "openid email profile")!,
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    userinfoUrl: "https://openidconnect.googleapis.com/v1/userinfo",
    revokeUrl: "https://oauth2.googleapis.com/revoke",
    apiUrl: env("GOOGLE_API_URL") || undefined,
    issuer: ["https://accounts.google.com", "accounts.google.com"],
    jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
    // offline + consent makes Google return a refresh token on every login (needed to test refresh).
    extraAuthParams: { access_type: "offline", prompt: env("GOOGLE_PROMPT", "consent")! },
    revokeWithClientAuth: false,
  });
}

const cfg = {
  port: Number(env("PORT", "4000")),
  baseUrl: trim(env("BASE_URL", "http://localhost:4000")!),
};
const redirectUri = `${cfg.baseUrl}/callback`;
const secureCookies = cfg.baseUrl.startsWith("https://");

// ---------------------------------------------------------------- sessions (in-memory)

interface Session {
  pending?: { provider: string; state: string; verifier: string; nonce: string; returnTo: string };
  provider?: string;
  tokens?: { access_token: string; refresh_token?: string; id_token?: string; expires_at?: number; scope?: string };
  idClaims?: JWTPayload;
  user?: Record<string, unknown>;
}
const sessions = new Map<string, Session>();
const rand = (n = 32) => randomBytes(n).toString("base64url");

function session(req: Request, res: Response): Session {
  const sid = req.headers.cookie?.match(/(?:^|;\s*)sid=([^;]+)/)?.[1];
  if (sid && sessions.has(sid)) return sessions.get(sid)!;
  const id = rand();
  const s: Session = {};
  sessions.set(id, s);
  res.cookie("sid", id, { httpOnly: true, sameSite: "lax", secure: secureCookies, path: "/" });
  return s;
}

function requireLogin(req: Request, res: Response, next: NextFunction) {
  const s = session(req, res);
  if (s.tokens && s.provider && providers.has(s.provider)) return next();
  res.redirect(`/?returnTo=${encodeURIComponent(req.originalUrl)}`);
}

// ---------------------------------------------------------------- HTTP helpers

async function tokenRequest(p: Provider, params: Record<string, string>) {
  const body = new URLSearchParams({ ...params, client_id: p.clientId });
  if (p.clientSecret) body.set("client_secret", p.clientSecret);
  const r = await fetch(p.tokenUrl, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
  });
  const json = (await r.json().catch(() => ({}))) as Record<string, any>;
  if (!r.ok || json.error) throw new Error(`Token endpoint ${r.status}: ${json.error ?? ""} ${json.error_description ?? ""}`.trim());
  return json;
}

async function getJson(url: string, accessToken: string) {
  const r = await fetch(url, { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" } });
  const text = await r.text();
  let body: unknown = text;
  try {
    body = JSON.parse(text);
  } catch {}
  return { status: r.status, body };
}

/** Full OIDC ID token validation: signature (provider JWKS), iss, aud, exp, and optionally nonce. */
async function verifyIdToken(p: Provider, idToken: string, nonce?: string) {
  const { payload } = await jwtVerify(idToken, p.jwks, { issuer: p.issuer, audience: p.clientId });
  if (nonce !== undefined && payload.nonce !== nonce) throw new Error("ID token nonce mismatch");
  return payload;
}

function storeTokens(s: Session, t: Record<string, any>) {
  s.tokens = {
    access_token: t.access_token,
    refresh_token: t.refresh_token ?? s.tokens?.refresh_token, // Google doesn't rotate refresh tokens
    id_token: t.id_token ?? s.tokens?.id_token,
    scope: t.scope,
    expires_at: t.expires_in ? Date.now() + Number(t.expires_in) * 1000 : undefined,
  };
}

const tryDecode = (jwt?: string) => {
  try {
    return jwt ? decodeJwt(jwt) : undefined;
  } catch {
    return undefined; // opaque token (e.g. Google access tokens)
  }
};

// ---------------------------------------------------------------- HTML

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const json = (v: unknown) => `<pre>${esc(JSON.stringify(v, null, 2))}</pre>`;

const layout = (title: string, s: Session, body: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · OAuth Test Client</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:860px;margin:0 auto;padding:0 16px 40px;color:#1c1c1c}
  nav{display:flex;gap:16px;align-items:center;padding:14px 0;border-bottom:1px solid #e3e3e3;margin-bottom:20px}
  nav .sp{flex:1} a{color:#2f5bd3} form{display:inline}
  button,.btn{display:inline-block;padding:7px 13px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;cursor:pointer;font:inherit;text-decoration:none}
  button.secondary{background:#e3e3e3;color:#1c1c1c} .btns{display:flex;gap:10px;flex-wrap:wrap}
  pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
  .err{color:#b42318} .ok{color:#067647} .muted{color:#666} h2{font-size:17px;margin-top:28px}
  table{border-collapse:collapse;margin-bottom:12px} td{padding:2px 12px 2px 0;vertical-align:top}
</style></head><body>
<nav><strong>OAuth Test Client</strong><a href="/">Home</a><a href="/profile">Profile (authed)</a><span class="sp"></span>
${s.tokens ? `<span class="muted">via ${esc(providers.get(s.provider!)?.name ?? "?")}</span><form method="post" action="/logout"><button class="secondary">Log out</button></form>` : ""}
</nav>
<h1>${esc(title)}</h1>${body}</body></html>`;

const safeReturnTo = (v: unknown) => (typeof v === "string" && v.startsWith("/") && !v.startsWith("//") ? v : "/profile");

// ---------------------------------------------------------------- app

const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false }));

app.get("/healthz", (_req, res) => res.send("ok"));

app.get("/", (req, res) => {
  const s = session(req, res);
  const returnTo = encodeURIComponent(safeReturnTo(req.query.returnTo));
  const buttons = [...providers.values()]
    .map((p) => `<a class="btn" href="/login?provider=${p.id}&returnTo=${returnTo}">Log in with ${esc(p.name)}</a>`)
    .join("");
  const configTables = [...providers.values()]
    .map((p) => {
      const rows: [string, string | undefined][] = [
        ["Client ID", p.clientId],
        ["Scopes", p.scopes],
        ["Authorize", p.authorizeUrl],
        ["Token", p.tokenUrl],
        ["Userinfo", p.userinfoUrl],
        ["JWKS", p.jwksUrl],
        ["API", p.apiUrl],
      ];
      return `<h2>${esc(p.name)} <span class="muted">(${p.id})</span></h2>
        <table>${rows.map(([k, v]) => `<tr><td class="muted">${k}</td><td><code>${esc(v ?? "—")}</code></td></tr>`).join("")}</table>`;
    })
    .join("");
  const googleHint = providers.has("google")
    ? ""
    : `<p class="muted">Google is disabled. Set <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code> (see README) to enable it.</p>`;

  res.send(
    layout(
      "Home",
      s,
      `${s.tokens ? `<p><span class="ok">Signed in.</span> Go to <a href="/profile">your profile</a>, or log in again with another provider:</p>` : `<p>Not signed in. Choose a provider to reach the protected page:</p>`}
       <div class="btns">${buttons}</div>${googleHint}
       <p class="muted">Redirect URI to register with every provider: <code>${esc(redirectUri)}</code></p>
       ${configTables}`,
    ),
  );
});

app.get("/login", (req, res) => {
  const s = session(req, res);
  const p = providers.get(String(req.query.provider ?? "local"));
  if (!p) return res.status(400).send(layout("Unknown provider", s, `<p class="err">Provider not configured.</p><p><a href="/">Back</a></p>`));

  const pending = { provider: p.id, state: rand(), verifier: rand(48), nonce: rand(), returnTo: safeReturnTo(req.query.returnTo) };
  s.pending = pending;

  const url = new URL(p.authorizeUrl);
  const params: Record<string, string> = {
    response_type: "code",
    client_id: p.clientId,
    redirect_uri: redirectUri,
    scope: p.scopes,
    state: pending.state,
    nonce: pending.nonce,
    code_challenge: createHash("sha256").update(pending.verifier).digest("base64url"),
    code_challenge_method: "S256",
    ...p.extraAuthParams,
  };
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  res.redirect(url.toString());
});

app.get("/callback", async (req, res) => {
  const s = session(req, res);
  const pending = s.pending;
  s.pending = undefined;
  const q = req.query as Record<string, string | undefined>;
  const fail = (msg: string) => res.status(400).send(layout("Login failed", s, `<p class="err">${esc(msg)}</p><p><a href="/">Try again</a></p>`));

  if (q.error) return fail(`Provider returned error: ${q.error}${q.error_description ? ` — ${q.error_description}` : ""}`);
  if (!pending || !q.state || q.state !== pending.state) return fail("State mismatch (possible CSRF, or the session expired). Start the login again.");
  const p = providers.get(pending.provider)!;
  // RFC 9207 mix-up defence: if the provider names itself, it must be the one we sent the user to.
  if (q.iss && ![p.issuer].flat().includes(q.iss)) return fail(`Unexpected issuer in callback: ${q.iss}`);
  if (!q.code) return fail("No authorization code in callback");

  try {
    const t = await tokenRequest(p, {
      grant_type: "authorization_code",
      code: q.code,
      redirect_uri: redirectUri,
      code_verifier: pending.verifier,
    });
    const idClaims = t.id_token ? await verifyIdToken(p, t.id_token, pending.nonce) : undefined;

    s.provider = p.id;
    s.tokens = undefined; // don't carry another provider's refresh token over
    storeTokens(s, t);
    s.idClaims = idClaims;
    s.user = idClaims as Record<string, unknown> | undefined;
    if (p.userinfoUrl) {
      const ui = await getJson(p.userinfoUrl, t.access_token);
      if (ui.status === 200 && typeof ui.body === "object") s.user = ui.body as Record<string, unknown>;
    }
    res.redirect(pending.returnTo);
  } catch (err) {
    fail((err as Error).message);
  }
});

app.get("/profile", requireLogin, async (req, res) => {
  const s = session(req, res);
  const p = providers.get(s.provider!)!;
  const t = s.tokens!;
  const api = p.apiUrl ? await getJson(p.apiUrl, t.access_token).catch((e) => ({ status: 0, body: String(e) })) : undefined;
  const expiresIn = t.expires_at ? Math.round((t.expires_at - Date.now()) / 1000) : undefined;
  const name = String(s.user?.name ?? s.user?.preferred_username ?? s.user?.email ?? s.user?.sub ?? "user");
  const picture = typeof s.user?.picture === "string" ? s.user.picture : undefined;
  const atClaims = tryDecode(t.access_token);

  res.send(
    layout(
      `Hello, ${name}`,
      s,
      `${picture ? `<img src="${esc(picture)}" alt="" width="64" height="64" style="border-radius:50%" referrerpolicy="no-referrer">` : ""}
       <p>Signed in with <strong>${esc(p.name)}</strong>. This page requires a login. Your tokens are stored on the server; the browser only holds a session cookie.</p>
       <p>Access token ${expiresIn === undefined ? "" : expiresIn > 0 ? `expires in <strong>${expiresIn}s</strong>` : `<span class="err">expired</span>`}
       ${t.refresh_token ? `<form method="post" action="/refresh"><button class="secondary">Refresh tokens</button></form>` : `<span class="muted">(no refresh token)</span>`}</p>

       <h2>User info</h2>${json(s.user ?? {})}
       ${api ? `<h2>Protected API: <code>GET ${esc(p.apiUrl!)}</code> → <span class="${api.status === 200 ? "ok" : "err"}">${api.status}</span></h2>${json(api.body)}` : ""}
       ${s.idClaims ? `<h2>ID token claims <span class="ok">(signature verified)</span></h2>${json(s.idClaims)}` : ""}
       <h2>Access token ${atClaims ? "claims" : `<span class="muted">(opaque, not a JWT)</span>`}</h2>${json(atClaims ?? { scope: t.scope })}`,
    ),
  );
});

app.post("/refresh", requireLogin, async (req, res) => {
  const s = session(req, res);
  const p = providers.get(s.provider!)!;
  try {
    const t = await tokenRequest(p, { grant_type: "refresh_token", refresh_token: s.tokens!.refresh_token ?? "" });
    if (t.id_token) s.idClaims = await verifyIdToken(p, t.id_token); // refreshed ID tokens carry no nonce
    storeTokens(s, t);
    res.redirect("/profile");
  } catch (err) {
    res.status(400).send(layout("Refresh failed", s, `<p class="err">${esc((err as Error).message)}</p>`));
  }
});

app.post("/logout", async (req, res) => {
  const s = session(req, res);
  const p = s.provider ? providers.get(s.provider) : undefined;
  if (p?.revokeUrl && s.tokens) {
    // Revoking the refresh token also revokes its access tokens at Google; local server needs both.
    for (const token of [s.tokens.refresh_token, s.tokens.access_token].filter(Boolean) as string[]) {
      const body = new URLSearchParams({ token });
      if (p.revokeWithClientAuth) {
        body.set("client_id", p.clientId);
        if (p.clientSecret) body.set("client_secret", p.clientSecret);
      }
      await fetch(p.revokeUrl, { method: "POST", body }).catch(() => {});
    }
  }
  s.tokens = s.user = s.idClaims = s.provider = undefined;
  res.redirect("/");
});

const server = app.listen(cfg.port, () =>
  console.log(`[oauth-client] ${cfg.baseUrl} — providers: ${[...providers.values()].map((p) => p.id).join(", ")} — redirect URI: ${redirectUri}`),
);
for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => server.close(() => process.exit(0)));
