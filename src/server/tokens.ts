import { createPublicKey, generateKeyPairSync, createHash } from "node:crypto";
import { SignJWT, jwtVerify, exportJWK, importPKCS8, importSPKI, type JWK, type JWTPayload, type CryptoKey } from "jose";
import { config, type UserConfig } from "./config.js";
import { randomToken, revokedJtis } from "./store.js";

const ALG = "RS256";

let privateKey: CryptoKey;
let publicKey: CryptoKey;
let publicJwk: JWK;

export async function initKeys() {
  let pem = config.signingKeyPem;
  if (!pem) {
    console.warn("[keys] SIGNING_KEY_PEM not set — generating an ephemeral RSA key (tokens won't survive restarts)");
    pem = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  }
  privateKey = await importPKCS8(pem, ALG);
  const spki = createPublicKey(pem).export({ type: "spki", format: "pem" }).toString();
  publicKey = await importSPKI(spki, ALG, { extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = createHash("sha256").update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })).digest("base64url").slice(0, 16);
  publicJwk = { ...jwk, kid, alg: ALG, use: "sig" };
}

export const getJwks = () => ({ keys: [publicJwk] });

export interface AccessTokenClaims extends JWTPayload {
  sub: string;
  client_id: string;
  scope: string;
  jti: string;
}

export async function signAccessToken(sub: string, clientId: string, scope: string[]) {
  return new SignJWT({ client_id: clientId, scope: scope.join(" ") })
    .setProtectedHeader({ alg: ALG, kid: publicJwk.kid, typ: "at+jwt" })
    .setIssuer(config.issuer)
    .setAudience(config.issuer) // this server's own /api is the resource server
    .setSubject(sub)
    .setJti(randomToken(16))
    .setIssuedAt()
    .setExpirationTime(`${config.accessTokenTtlSec}s`)
    .sign(privateKey);
}

export async function signIdToken(user: UserConfig, clientId: string, scope: string[], nonce?: string) {
  const claims: Record<string, unknown> = { auth_time: Math.floor(Date.now() / 1000) };
  if (nonce) claims.nonce = nonce;
  Object.assign(claims, userClaims(user, scope));
  return new SignJWT(claims)
    .setProtectedHeader({ alg: ALG, kid: publicJwk.kid, typ: "JWT" })
    .setIssuer(config.issuer)
    .setAudience(clientId)
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime(`${config.accessTokenTtlSec}s`)
    .sign(privateKey);
}

/** Returns verified claims, or null if the token is invalid, expired, or revoked. */
export async function verifyAccessToken(token: string): Promise<AccessTokenClaims | null> {
  try {
    const { payload } = await jwtVerify<AccessTokenClaims>(token, publicKey, {
      issuer: config.issuer,
      audience: config.issuer,
      typ: "at+jwt",
      algorithms: [ALG],
    });
    if (revokedJtis.has(payload.jti)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function userClaims(user: UserConfig, scope: string[]) {
  const out: Record<string, unknown> = { sub: user.id };
  if (scope.includes("profile")) Object.assign(out, { name: user.name, preferred_username: user.username });
  if (scope.includes("email")) Object.assign(out, { email: user.email, email_verified: true });
  return out;
}
