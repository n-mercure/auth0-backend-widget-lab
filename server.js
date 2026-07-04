const http = require("http");
const crypto = require("crypto");
const { URL, URLSearchParams } = require("url");

loadEnv();

const config = {
  port: process.env.PORT || "3000",
  baseUrl: stripTrailingSlash(required("BASE_URL")),
  auth0Domain: required("AUTH0_DOMAIN"),
  clientId: required("AUTH0_CLIENT_ID"),
  clientSecret: required("AUTH0_CLIENT_SECRET"),
  sessionSecret: required("SESSION_SECRET"),
};

const issuer = `https://${config.auth0Domain}`;

function loadEnv() {
  const fs = require("fs");
  const path = require("path");
  const envPath = path.join(__dirname, ".env");
  if (!fs.existsSync(envPath)) return;

  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const separator = trimmed.indexOf("=");
    if (separator === -1) continue;

    const key = trimmed.slice(0, separator).trim();
    const value = trimmed.slice(separator + 1).trim().replace(/^"|"$/g, "");

    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

function required(name) {
  if (!process.env[name]) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return process.env[name];
}

function stripTrailingSlash(value) {
  return value.replace(/\/$/, "");
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  for (const part of header.split(";")) {
    const [rawName, ...rawValue] = part.trim().split("=");
    if (!rawName) continue;
    cookies[rawName] = rawValue.join("=");
  }

  return cookies;
}

function sign(value) {
  return crypto
    .createHmac("sha256", config.sessionSecret)
    .update(value)
    .digest("base64url");
}

function createCookieValue(payload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${body}.${sign(body)}`;
}

function readCookieValue(value) {
  if (!value || !value.includes(".")) return null;

  const [body, signature] = value.split(".");
  const expected = sign(body);

  if (
    signature.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))
  ) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

function setCookie(res, name, payload, maxAgeSeconds) {
  const secure = config.baseUrl.startsWith("https://") ? " Secure;" : "";
  const value = createCookieValue(payload);

  res.setHeader("Set-Cookie", [
    `${name}=${value}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`,
  ]);
}

function clearCookie(res, name) {
  const secure = config.baseUrl.startsWith("https://") ? " Secure;" : "";

  res.setHeader("Set-Cookie", [
    `${name}=; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=0`,
  ]);
}

function getSession(req) {
  const cookies = parseCookies(req);
  return readCookieValue(cookies.app_session);
}

function getLoginTransaction(req) {
  const cookies = parseCookies(req);
  return readCookieValue(cookies.login_transaction);
}

function randomValue() {
  return crypto.randomBytes(32).toString("base64url");
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(302, {
    Location: location,
    ...extraHeaders,
  });
  res.end();
}

function html(res, body, status = 200) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });

  res.end(`<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Auth0 Backend Lab v0.1</title>
  <style>
    body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; line-height: 1.5; color: #172033; }
    main { max-width: 920px; margin: 0 auto; }
    .card { border: 1px solid #d0d7de; border-radius: 12px; padding: 16px; margin: 16px 0; background: #f6f8fa; }
    .button { display: inline-block; background: #172033; color: #fff; padding: 10px 14px; border-radius: 8px; text-decoration: none; font-weight: 600; }
    .secondary { background: #fff; color: #172033; border: 1px solid #172033; }
    pre { white-space: pre-wrap; word-break: break-word; background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 12px; }
  </style>
</head>
<body>
  <main>
    ${body}
  </main>
</body>
</html>`);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderHome(req, res) {
  const session = getSession(req);

  html(res, `
    <h1>Auth0 Backend Lab v0.1</h1>
    <p>Objectif : valider uniquement l'authentification backend avant d'ajouter le widget.</p>

    <div class="card">
      <h2>État</h2>
      <pre>${escapeHtml(JSON.stringify({ authenticated: Boolean(session), user: session?.user || null }, null, 2))}</pre>
    </div>

    <p>
      <a class="button" href="/protected">Ouvrir /protected</a>
      ${session ? '<a class="button secondary" href="/logout">Logout</a>' : '<a class="button secondary" href="/login">Login</a>'}
    </p>
  `);
}

function renderProtected(req, res) {
  const session = getSession(req);

  if (!session) {
    return redirect(res, "/login");
  }

  html(res, `
    <h1>Page protégée côté backend</h1>
    <p>Cette page est rendue seulement parce que le backend a validé une session applicative serveur.</p>

    <div class="card">
      <h2>Utilisateur</h2>
      <pre>${escapeHtml(JSON.stringify(session.user, null, 2))}</pre>
    </div>

    <div class="card">
      <h2>Timeline v0.1</h2>
      <pre>GET /protected
Backend: session trouvée
Backend: rendu HTML autorisé</pre>
    </div>

    <p>
      <a class="button secondary" href="/">Accueil</a>
      <a class="button secondary" href="/logout">Logout</a>
    </p>
  `);
}

function startLogin(req, res) {
  const state = randomValue();
  const nonce = randomValue();

  const authorizeUrl = `${issuer}/authorize?${new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: `${config.baseUrl}/callback`,
    scope: "openid profile email",
    state,
    nonce,
  })}`;

  const cookieValue = createCookieValue({
    state,
    nonce,
    createdAt: Date.now(),
  });

  const secure = config.baseUrl.startsWith("https://") ? " Secure;" : "";
  const headers = {
    "Set-Cookie": `login_transaction=${cookieValue}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=600`,
  };

  redirect(res, authorizeUrl, headers);
}

async function handleCallback(req, res, url) {
  const error = url.searchParams.get("error");
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (error) {
    return html(res, `
      <h1>Auth0 error</h1>
      <pre>${escapeHtml(url.searchParams.toString())}</pre>
    `, 400);
  }

  const transaction = getLoginTransaction(req);

  if (!transaction || transaction.state !== state) {
    return html(res, `
      <h1>Invalid OAuth state</h1>
      <p>Le callback ne correspond pas à une transaction de login démarrée par ce navigateur.</p>
    `, 400);
  }

  try {
    const tokens = await exchangeCode(code);
    const user = await fetchUserInfo(tokens.access_token);

    const appSession = createCookieValue({
      user,
      createdAt: new Date().toISOString(),
    });

    const secure = config.baseUrl.startsWith("https://") ? " Secure;" : "";

    res.writeHead(302, {
      Location: "/protected",
      "Set-Cookie": [
        `login_transaction=; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=0`,
        `app_session=${appSession}; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=3600`,
      ],
    });
    res.end();
  } catch (err) {
    html(res, `
      <h1>Callback failed</h1>
      <pre>${escapeHtml(err.stack || err.message)}</pre>
    `, 500);
  }
}

async function exchangeCode(code) {
  const response = await fetch(`${issuer}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      client_id: config.clientId,
      client_secret: config.clientSecret,
      code,
      redirect_uri: `${config.baseUrl}/callback`,
    }),
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${JSON.stringify(json)}`);
  }

  return json;
}

async function fetchUserInfo(accessToken) {
  const response = await fetch(`${issuer}/userinfo`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  const json = await response.json();

  if (!response.ok) {
    throw new Error(`UserInfo failed: ${JSON.stringify(json)}`);
  }

  return {
    sub: json.sub,
    name: json.name,
    email: json.email,
    picture: json.picture,
  };
}

function logout(req, res) {
  const secure = config.baseUrl.startsWith("https://") ? " Secure;" : "";

  const auth0LogoutUrl = `${issuer}/v2/logout?${new URLSearchParams({
    client_id: config.clientId,
    returnTo: config.baseUrl,
  })}`;

  res.writeHead(302, {
    Location: auth0LogoutUrl,
    "Set-Cookie": [
      `app_session=; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=0`,
      `login_transaction=; HttpOnly;${secure} SameSite=Lax; Path=/; Max-Age=0`,
    ],
  });
  res.end();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, config.baseUrl);

  if (url.pathname === "/") return renderHome(req, res);
  if (url.pathname === "/protected") return renderProtected(req, res);
  if (url.pathname === "/login") return startLogin(req, res);
  if (url.pathname === "/callback") return handleCallback(req, res, url);
  if (url.pathname === "/logout") return logout(req, res);

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(Number(config.port), () => {
  console.log(`Auth0 Backend Lab v0.1 running on ${config.baseUrl}`);
});
