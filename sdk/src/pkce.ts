// Isomorphic helpers (Web Crypto) — work in Node 20+, browsers, Deno, Bun, and edge runtimes.

export function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Cryptographically random base64url string from `bytes` random bytes (32 → 43 chars). */
export function randomString(bytes = 32): string {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** A fresh PKCE verifier (43 chars, within RFC 7636's 43–128). */
export const createCodeVerifier = () => randomString(32);

/** S256 code challenge for a verifier: BASE64URL(SHA256(verifier)). */
export async function createCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}
