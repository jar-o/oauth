export interface ClientConfig {
  clientId: string;
  /** Omit for public clients (SPAs, native apps) — they must use PKCE. */
  clientSecret?: string;
  redirectUris: string[];
  allowedScopes: string[];
  name: string;
}

export interface UserConfig {
  id: string;
  username: string;
  password: string;
  name: string;
  email: string;
}

const env = (key: string, fallback: string) => process.env[key] ?? fallback;

export const config = {
  port: Number(env("PORT", "3000")),
  /** Public URL that browsers and token consumers see. Used as the `iss` claim. */
  issuer: env("ISSUER", "http://localhost:3000").replace(/\/$/, ""),
  accessTokenTtlSec: Number(env("ACCESS_TOKEN_TTL", "900")),
  refreshTokenTtlSec: Number(env("REFRESH_TOKEN_TTL", "86400")),
  authCodeTtlSec: 60,
  /** Directory for the RocksDB datastore. Must be writable and used by one process only. */
  dataDir: env("DATA_DIR", "./data"),
  /** Optional PEM-encoded PKCS#8 RSA private key. If unset, one is generated once and stored in the DB. */
  signingKeyPem: process.env.SIGNING_KEY_PEM,
  supportedScopes: ["openid", "profile", "email", "read", "write", "offline_access"],

  clients: parseJson<ClientConfig[]>("CLIENTS_JSON", [
    {
      clientId: env("DEMO_CLIENT_ID", "demo-client"),
      clientSecret: env("DEMO_CLIENT_SECRET", "demo-secret"),
      redirectUris: env("DEMO_CLIENT_REDIRECT_URIS", "http://localhost:4000/callback").split(","),
      allowedScopes: ["openid", "profile", "email", "read", "write", "offline_access"],
      name: "Demo Test Client",
    },
  ]),

  users: parseJson<UserConfig[]>("USERS_JSON", [
    { id: "u-1001", username: "alice", password: "password", name: "Alice Example", email: "alice@example.com" },
    { id: "u-1002", username: "bob", password: "password", name: "Bob Example", email: "bob@example.com" },
  ]),
};

function parseJson<T>(key: string, fallback: T): T {
  const raw = process.env[key];
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    throw new Error(`Invalid JSON in env var ${key}: ${(err as Error).message}`);
  }
}
