\
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { URL, URLSearchParams } = require("url");

loadDotEnv();

const CONFIG = {
  port: process.env.PORT || "3000",
  domain: requiredEnv("AUTH0_DOMAIN"),
  backendClientId: requiredEnv("AUTH0_CLIENT_ID"),
  backendClientSecret: requiredEnv("AUTH0_CLIENT_SECRET"),
  baseUrl: normalizeBaseUrl(requiredEnv("BASE_URL")),
  sessionSecret: requiredEnv("SESSION_SECRET"),
  widgetClientId: requiredEnv("WIDGET_AUTH0_CLIENT_ID"),
  widgetAudience: requiredEnv("WIDGET_API_AUDIENCE"),
};

const ISSUER = `https://${CONFIG.domain}/`;

function loadDotEnv() {
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;

  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const idx = trimmed.indexOf("=");
    if (idx === -1) continue;
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim().replace(/^"|"$/g, "");
    if (!process.env[key]) process.env[key] = value;
  }
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function normalizeBaseUrl(value) {
  return value.replace(/\/$/, "");
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

function randomBase64Url(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function sign(value) {
  return crypto.createHmac("sha256", CONFIG.sessionSecret).update(value).digest("base64url");
}

function serializeCookie(name, value, options = {}) {
  const parts = [`${name}=${value}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.path) parts.push(`Path=${options.path}`);
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  return parts.join("; ");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return Object.fromEntries(
    header.split(";").map(v => v.trim()).filter(Boolean).map(pair => {
      const idx = pair.indexOf("=");
      return [pair.slice(0, idx), pair.slice(idx + 1)];
    })
  );
}

function createSignedCookiePayload(payload) {
  const encoded = base64url(JSON.stringify(payload));
  return `${encoded}.${sign(encoded)}`;
}

function readSignedCookie(req, name) {
  const cookies = parseCookies(req);
  const raw = cookies[name];
  if (!raw || !raw.includes(".")) return null;
  const [encoded, sig] = raw.split(".");
  const expected = sign(encoded);
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function setCookie(res, name, payload, maxAgeSeconds = 3600) {
  const cookie = serializeCookie(name, createSignedCookiePayload(payload), {
    httpOnly: true,
    secure: CONFIG.baseUrl.startsWith("https://"),
    sameSite: "Lax",
    path: "/",
    maxAge: maxAgeSeconds,
  });
  res.setHeader("Set-Cookie", cookie);
}

function clearCookie(res, name) {
  res.setHeader("Set-Cookie", serializeCookie(name, "", {
    httpOnly: true,
    secure: CONFIG.baseUrl.startsWith("https://"),
    sameSite: "Lax",
    path: "/",
    maxAge: 0,
  }));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end();
}

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

function sendJson(res, body, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body, null, 2));
}

function sendText(res, text, status = 200) {
  res.writeHead(status, { "Content-Type": "text/plain; charset=utf-8" });
  res.end(text);
}

function renderLayout(title, body) {
  return `<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <link rel="stylesheet" href="/public/styles.css" />
</head>
<body>
  <main class="page">
    ${body}
  </main>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getSession(req) {
  return readSignedCookie(req, "app_session");
}

function getLoginState(req) {
  return readSignedCookie(req, "login_state");
}

function requireSession(req, res) {
  const session = getSession(req);
  if (session) return session;
  redirect(res, "/login");
  return null;
}

function buildAuthorizeUrl() {
  const state = randomBase64Url();
  const nonce = randomBase64Url();
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CONFIG.backendClientId,
    redirect_uri: `${CONFIG.baseUrl}/callback`,
    scope: "openid profile email",
    state,
    nonce,
  });

  return {
    url: `${ISSUER}authorize?${params.toString()}`,
    state,
    nonce,
  };
}

async function exchangeCodeForTokens(code) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: CONFIG.backendClientId,
    client_secret: CONFIG.backendClientSecret,
    code,
    redirect_uri: `${CONFIG.baseUrl}/callback`,
  });

  const response = await fetch(`${ISSUER}oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const json = await response.json();
  if (!response.ok) {
    throw new Error(`Token exchange failed: ${JSON.stringify(json)}`);
  }
  return json;
}

let jwksCache = null;

async function getJwks() {
  if (jwksCache) return jwksCache;
  const response = await fetch(`${ISSUER}.well-known/jwks.json`);
  if (!response.ok) throw new Error("Unable to fetch JWKS");
  jwksCache = await response.json();
  return jwksCache;
}

function decodeJwt(token) {
  const [headerB64, payloadB64, signatureB64] = token.split(".");
  if (!headerB64 || !payloadB64 || !signatureB64) throw new Error("Invalid JWT shape");
  return {
    header: JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")),
    payload: JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")),
    signingInput: `${headerB64}.${payloadB64}`,
    signature: Buffer.from(signatureB64, "base64url"),
  };
}

async function verifyJwt(token, expectedAudience, expectedNonce) {
  const decoded = decodeJwt(token);
  if (decoded.header.alg !== "RS256") throw new Error(`Unexpected alg: ${decoded.header.alg}`);

  const jwks = await getJwks();
  const jwk = jwks.keys.find(k => k.kid === decoded.header.kid);
  if (!jwk) throw new Error("Unable to find matching JWK");

  const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
  const validSignature = crypto.verify(
    "RSA-SHA256",
    Buffer.from(decoded.signingInput),
    key,
    decoded.signature
  );
  if (!validSignature) throw new Error("JWT signature verification failed");

  const payload = decoded.payload;
  const now = Math.floor(Date.now() / 1000);

  if (payload.iss !== ISSUER) throw new Error(`Invalid issuer: ${payload.iss}`);
  if (expectedAudience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(expectedAudience)) throw new Error(`Invalid audience: ${payload.aud}`);
  }
  if (payload.exp && payload.exp < now) throw new Error("JWT expired");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("Invalid nonce");

  return payload;
}

async function handleHome(req, res) {
  const session = getSession(req);
  const body = `
    <h1>Auth0 Backend + Widget Lab</h1>
    <p>Ce lab valide un scénario backend-rendered : la page est protégée côté serveur, puis le widget obtient son propre token silencieusement.</p>
    <div class="actions">
      ${session ? `<a class="button" href="/protected">Ouvrir la page protégée</a>` : `<a class="button" href="/login">Login backend</a>`}
      ${session ? `<a class="button secondary" href="/logout">Logout</a>` : ""}
    </div>
    <section class="card">
      <h2>État serveur</h2>
      <pre>${escapeHtml(JSON.stringify({ authenticated: Boolean(session), user: session?.user || null }, null, 2))}</pre>
    </section>
  `;
  sendHtml(res, renderLayout("Auth0 Lab", body));
}

async function handleLogin(req, res) {
  const auth = buildAuthorizeUrl();
  setCookie(res, "login_state", { state: auth.state, nonce: auth.nonce }, 600);
  redirect(res, auth.url);
}

async function handleCallback(req, res, parsedUrl) {
  const code = parsedUrl.searchParams.get("code");
  const state = parsedUrl.searchParams.get("state");
  const error = parsedUrl.searchParams.get("error");

  if (error) {
    return sendHtml(res, renderLayout("Auth0 Error", `<h1>Auth0 Error</h1><pre>${escapeHtml(parsedUrl.search)}</pre>`), 400);
  }

  const loginState = getLoginState(req);
  if (!loginState || loginState.state !== state) {
    return sendText(res, "Invalid or missing OAuth state.", 400);
  }

  try {
    const tokens = await exchangeCodeForTokens(code);
    const user = await verifyJwt(tokens.id_token, CONFIG.backendClientId, loginState.nonce);

    const headers = [];
    headers.push(serializeCookie("login_state", "", {
      httpOnly: true,
      secure: CONFIG.baseUrl.startsWith("https://"),
      sameSite: "Lax",
      path: "/",
      maxAge: 0,
    }));
    headers.push(serializeCookie("app_session", createSignedCookiePayload({
      user: {
        sub: user.sub,
        name: user.name,
        email: user.email,
        picture: user.picture,
      },
      createdAt: new Date().toISOString(),
    }), {
      httpOnly: true,
      secure: CONFIG.baseUrl.startsWith("https://"),
      sameSite: "Lax",
      path: "/",
      maxAge: 3600,
    }));

    res.writeHead(302, { Location: "/protected", "Set-Cookie": headers });
    res.end();
  } catch (err) {
    sendHtml(res, renderLayout("Callback failed", `<h1>Callback failed</h1><pre>${escapeHtml(err.stack || err.message)}</pre>`), 500);
  }
}

async function handleProtected(req, res) {
  const session = requireSession(req, res);
  if (!session) return;

  const body = `
    <h1>Page protégée côté backend</h1>
    <p>Cette page n'est rendue qu'après validation d'une session applicative serveur.</p>

    <section class="card">
      <h2>Session serveur</h2>
      <pre>${escapeHtml(JSON.stringify(session, null, 2))}</pre>
    </section>

    <section class="card">
      <h2>Widget embarqué</h2>
      <p>Le widget ci-dessous est chargé après le rendu backend. Il tente ensuite un <code>getTokenSilently()</code> avec le client SPA du widget.</p>
      <iframe class="widget-frame" src="/public/widget.html"></iframe>
    </section>

    <div class="actions">
      <a class="button secondary" href="/logout">Logout</a>
      <a class="button secondary" href="/">Accueil</a>
    </div>
  `;

  sendHtml(res, renderLayout("Protected", body));
}

async function handleLogout(req, res) {
  const logoutUrl = `${ISSUER}v2/logout?${new URLSearchParams({
    client_id: CONFIG.backendClientId,
    returnTo: CONFIG.baseUrl,
  }).toString()}`;

  clearCookie(res, "app_session");
  redirect(res, logoutUrl);
}

function handleConfig(req, res) {
  sendJson(res, {
    domain: CONFIG.domain,
    widgetClientId: CONFIG.widgetClientId,
    widgetAudience: CONFIG.widgetAudience,
    baseUrl: CONFIG.baseUrl,
  });
}

async function handleApiWidgetData(req, res) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : null;
  if (!token) {
    return sendJson(res, { error: "missing_bearer_token" }, 401);
  }

  try {
    const claims = await verifyJwt(token, CONFIG.widgetAudience, null);
    sendJson(res, {
      ok: true,
      message: "Widget API token accepted by backend API.",
      tokenClaims: {
        iss: claims.iss,
        sub: claims.sub,
        aud: claims.aud,
        azp: claims.azp,
        scope: claims.scope,
        exp: claims.exp,
      },
    });
  } catch (err) {
    sendJson(res, { ok: false, error: err.message }, 401);
  }
}

function serveStatic(req, res, pathname) {
  const publicRoot = path.join(__dirname, "public");
  const requested = path.normalize(path.join(__dirname, pathname));
  if (!requested.startsWith(publicRoot)) return sendText(res, "Forbidden", 403);

  fs.readFile(requested, (err, data) => {
    if (err) return sendText(res, "Not found", 404);
    const ext = path.extname(requested).toLowerCase();
    const contentType = {
      ".html": "text/html; charset=utf-8",
      ".js": "text/javascript; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".json": "application/json; charset=utf-8",
    }[ext] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": contentType });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url, CONFIG.baseUrl);
    const pathname = parsedUrl.pathname;

    if (pathname === "/") return handleHome(req, res);
    if (pathname === "/login") return handleLogin(req, res);
    if (pathname === "/callback") return handleCallback(req, res, parsedUrl);
    if (pathname === "/protected") return handleProtected(req, res);
    if (pathname === "/logout") return handleLogout(req, res);
    if (pathname === "/config.json") return handleConfig(req, res);
    if (pathname === "/api/widget-data") return handleApiWidgetData(req, res);
    if (pathname.startsWith("/public/")) return serveStatic(req, res, pathname);

    return sendText(res, "Not found", 404);
  } catch (err) {
    return sendHtml(res, renderLayout("Server error", `<h1>Server error</h1><pre>${escapeHtml(err.stack || err.message)}</pre>`), 500);
  }
});

server.listen(Number(CONFIG.port), () => {
  console.log(`Auth0 backend widget lab running on ${CONFIG.baseUrl}`);
});
