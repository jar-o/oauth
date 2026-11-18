import express from "express";
import { config } from "./config.js";
import { oauthRouter } from "./oauth.js";
import { apiRouter } from "./api.js";
import { initKeys } from "./tokens.js";
import { sweepExpired } from "./store.js";
import { closeDb, openDb } from "./db.js";

openDb();
await initKeys();

const app = express();
app.disable("x-powered-by");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.get("/healthz", (_req, res) => res.send("ok"));
app.use(oauthRouter);
app.use("/api", apiRouter);

setInterval(sweepExpired, 60_000).unref();

const server = app.listen(config.port, () => {
  console.log(`[oauth-server] issuer=${config.issuer} listening on :${config.port}`);
  console.log(`[oauth-server] clients: ${config.clients.map((c) => c.clientId).join(", ")}`);
});

// Close the DB after in-flight requests finish so RocksDB flushes and releases its lock cleanly.
for (const sig of ["SIGTERM", "SIGINT"] as const)
  process.on(sig, () =>
    server.close(() => {
      closeDb();
      process.exit(0);
    }),
  );
