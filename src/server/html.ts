export const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const page = (title: string, body: string) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:420px;margin:60px auto;padding:0 16px;color:#1c1c1c}
  h1{font-size:22px} label{display:block;margin:10px 0} input{display:block;width:100%;padding:8px;margin-top:4px;box-sizing:border-box}
  button{padding:8px 14px;border:0;border-radius:6px;background:#2f5bd3;color:#fff;cursor:pointer}
  button.secondary{background:#e3e3e3;color:#1c1c1c} .row{display:flex;gap:8px;margin-top:14px}
  .err{color:#b42318} .muted{color:#666;font-size:13px}
</style></head>
<body><h1>OAuth2 Server · ${escapeHtml(title)}</h1>${body}</body></html>`;
