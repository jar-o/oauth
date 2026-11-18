import { Router, type NextFunction, type Request, type Response } from "express";
import { verifyAccessToken, type AccessTokenClaims } from "./tokens.js";

declare module "express-serve-static-core" {
  interface Request {
    auth?: AccessTokenClaims;
  }
}

/** Bearer-token middleware. Optionally requires every listed scope. */
export function requireAuth(...scopes: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1];
    const claims = token ? await verifyAccessToken(token) : null;
    if (!claims) {
      res.status(401).set("WWW-Authenticate", 'Bearer error="invalid_token"').json({ error: "invalid_token" });
      return;
    }
    const granted = claims.scope.split(" ");
    const missing = scopes.filter((s) => !granted.includes(s));
    if (missing.length) {
      res
        .status(403)
        .set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="${scopes.join(" ")}"`)
        .json({ error: "insufficient_scope", missing });
      return;
    }
    req.auth = claims;
    next();
  };
}

/** Example protected resource API. */
export const apiRouter = Router();

apiRouter.get("/me", requireAuth(), (req, res) => {
  res.json({ message: "You presented a valid access token", token: req.auth });
});

apiRouter.get("/data", requireAuth("read"), (req, res) => {
  res.json({
    owner: req.auth!.sub,
    items: [
      { id: 1, name: "Widget", qty: 3 },
      { id: 2, name: "Gadget", qty: 7 },
    ],
  });
});

const notes: { by: string; text: string; at: string }[] = [];
apiRouter.post("/notes", requireAuth("write"), (req, res) => {
  const text = String(req.body?.text ?? "").slice(0, 500);
  if (!text) return void res.status(400).json({ error: "text is required" });
  const note = { by: req.auth!.sub, text, at: new Date().toISOString() };
  notes.push(note);
  res.status(201).json(note);
});
apiRouter.get("/notes", requireAuth("read"), (_req, res) => res.json(notes));
