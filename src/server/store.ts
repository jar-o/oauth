import { randomBytes } from "node:crypto";
import { Collection } from "./db.js";

/**
 * Persistent server state, backed by RocksDB (see db.ts). Every record carries an absolute
 * `expiresAt`; reads treat expired records as missing, and `sweepExpired()` deletes them.
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

export interface Note {
  by: string;
  text: string;
  at: string;
}

export const authCodes = new Collection<AuthCode>("auth_codes");
export const refreshTokens = new Collection<RefreshToken>("refresh_tokens");
/** jti -> { expiresAt }. Revoked access tokens, kept until they would have expired anyway. */
export const revokedJtis = new Collection<{ expiresAt: number }>("revoked_jtis");
/** Keyed by zero-padded timestamp so range scans return notes in creation order. */
export const notes = new Collection<Note>("notes");
/** Small server-wide values, e.g. the generated signing key. */
export const meta = new Collection<string>("meta");

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

const live = <T extends { expiresAt: number }>(v: T | undefined) => (v && v.expiresAt > Date.now() ? v : undefined);

/** Take-and-delete so codes are strictly single use. */
export const consumeAuthCode = (code: string) => live(authCodes.take(code));

export const getRefreshToken = (token: string) => live(refreshTokens.get(token));

export const isJtiRevoked = (jti: string) => revokedJtis.has(jti);

export function addNote(note: Note): Note {
  notes.put(`${String(Date.now()).padStart(15, "0")}-${randomToken(4)}`, note);
  return note;
}

export const listNotes = (): Note[] => [...notes.entries()].map(([, n]) => n);

export function sweepExpired(): void {
  const now = Date.now();
  const expired = (v: { expiresAt: number }) => v.expiresAt < now;
  const n = authCodes.deleteWhere(expired) + refreshTokens.deleteWhere(expired) + revokedJtis.deleteWhere(expired);
  if (n) console.log(`[db] swept ${n} expired records`);
}
