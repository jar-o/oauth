/** An OAuth protocol error (RFC 6749 §5.2), from the token endpoint or an authorization callback. */
export class OAuthError extends Error {
  override readonly name = "OAuthError";
  constructor(
    /** e.g. `invalid_grant`, `invalid_client`, `access_denied`, or `state_mismatch` (SDK-side). */
    readonly error: string,
    readonly description?: string,
    /** HTTP status, when the error came from an HTTP response. */
    readonly status?: number,
  ) {
    super(description ? `${error}: ${description}` : error);
  }
}

/** A non-2xx response from the resource API. */
export class ApiError extends Error {
  override readonly name = "ApiError";
  /** `error` field of the JSON body, e.g. `invalid_token` or `insufficient_scope`. */
  readonly code?: string;
  /** Scopes the token lacked (403 `insufficient_scope` only). */
  readonly missingScopes: string[];

  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    const b = (typeof body === "object" && body !== null ? body : {}) as { error?: string; missing?: string[] };
    super(`API request failed with ${status}${b.error ? ` (${b.error})` : ""}`);
    this.code = b.error;
    this.missingScopes = Array.isArray(b.missing) ? b.missing : [];
  }
}
