// Machine-to-machine example. Run the server first (`npm run dev:server` in the repo root), then:
//   cd sdk && npm run example
import { ApiClient, ApiError, ClientCredentialsTokenProvider, OAuthClient } from "../src/index.js";

const issuer = process.env.ISSUER ?? "http://localhost:3000";

const oauth = new OAuthClient({
  issuer,
  clientId: process.env.CLIENT_ID ?? "demo-client",
  clientSecret: process.env.CLIENT_SECRET ?? "demo-secret",
});

const api = new ApiClient({
  baseUrl: issuer,
  auth: new ClientCredentialsTokenProvider(oauth, "read"),
});

const me = await api.me();
console.log("token sub:", me.token.sub, "| scope:", me.token.scope);

const data = await api.getData();
console.log("items:", data.items);

try {
  await api.createNote("hello"); // needs `write`, which we didn't request
} catch (err) {
  if (err instanceof ApiError && err.code === "insufficient_scope") {
    console.log("createNote rejected as expected, missing scopes:", err.missingScopes);
  } else throw err;
}
