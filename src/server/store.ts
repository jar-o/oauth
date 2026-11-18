import { randomBytes } from "node:crypto";

/**
 * In-memory storage. Fine for a demo / single replica; swap for Redis or a DB
 * before running more than one instance.
 */

export interface AuthCode {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string[];
  codeChallenge: string;
  nonce?: string;
  expiresAt: number;
}

export interface RefreshToken {
  clientId: string;
  userId: string;
  scope: string[];
  expiresAt: number;
}

export const authCodes = new Map<string, AuthCode>();
export const refreshTokens = new Map<string, RefreshToken>();
/** jti -> expiry (ms). Revoked access tokens, kept until they would have expired anyway. */
export const revokedJtis = new Map<string, number>();

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

/** Take-and-delete so codes are strictly single use. */
export function consumeAuthCode(code: string): AuthCode | undefined {
  const entry = authCodes.get(code);
  authCodes.delete(code);
  if (!entry || entry.expiresAt < Date.now()) return undefined;
  return entry;
}

export function sweepExpired() {
  const now = Date.now();
  for (const [k, v] of authCodes) if (v.expiresAt < now) authCodes.delete(k);
  for (const [k, v] of refreshTokens) if (v.expiresAt < now) refreshTokens.delete(k);
  for (const [k, exp] of revokedJtis) if (exp < now) revokedJtis.delete(k);
}
