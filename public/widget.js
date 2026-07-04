let auth0Client = null;
let lastAccessToken = null;

const statusEl = document.getElementById("status");
const logsEl = document.getElementById("logs");
const silentAuthBtn = document.getElementById("silentAuthBtn");
const callApiBtn = document.getElementById("callApiBtn");
const clearCacheBtn = document.getElementById("clearCacheBtn");

function log(message, data) {
  const time = new Date().toLocaleTimeString();
  const suffix = data ? "\n" + JSON.stringify(data, null, 2) : "";
  logsEl.textContent += `[${time}] ${message}${suffix}\n\n`;
  logsEl.scrollTop = logsEl.scrollHeight;
}

function setStatus(value) {
  statusEl.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2);
}

function decodeJwtPayload(token) {
  const payload = token.split(".")[1];
  return JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
}

async function init() {
  log("Loading /config.json");
  const config = await fetch("/config.json").then(r => r.json());

  log("Creating Auth0 SPA client", {
    domain: config.domain,
    clientId: config.widgetClientId,
    audience: config.widgetAudience
  });

  auth0Client = await auth0.createAuth0Client({
    domain: config.domain,
    clientId: config.widgetClientId,
    authorizationParams: {
      audience: config.widgetAudience,
      redirect_uri: `${window.location.origin}/public/widget.html`
    },
    cacheLocation: "localstorage",
    useRefreshTokens: true
  });

  setStatus("Widget initialisé. Cliquez sur getTokenSilently().");
  log("Widget ready");
}

async function getTokenSilently() {
  try {
    log("Calling getTokenSilently()");
    lastAccessToken = await auth0Client.getTokenSilently({
      authorizationParams: {
        audience: (await fetch("/config.json").then(r => r.json())).widgetAudience
      }
    });

    const claims = decodeJwtPayload(lastAccessToken);
    callApiBtn.disabled = false;

    setStatus({
      authenticatedSilently: true,
      tokenPrefix: lastAccessToken.slice(0, 24) + "…",
      claims: {
        iss: claims.iss,
        sub: claims.sub,
        aud: claims.aud,
        azp: claims.azp,
        scope: claims.scope,
        exp: claims.exp
      }
    });

    log("Silent token received", {
      tokenPrefix: lastAccessToken.slice(0, 24) + "…",
      claims
    });
  } catch (err) {
    setStatus({
      authenticatedSilently: false,
      error: err.error || err.message,
      errorDescription: err.error_description
    });
    log("getTokenSilently() failed", {
      error: err.error || err.message,
      errorDescription: err.error_description
    });
  }
}

async function callProtectedApi() {
  if (!lastAccessToken) {
    setStatus("No access token yet.");
    return;
  }

  log("Calling /api/widget-data with Bearer token");
  const response = await fetch("/api/widget-data", {
    headers: {
      Authorization: `Bearer ${lastAccessToken}`
    }
  });
  const json = await response.json();
  setStatus(json);
  log("API response", json);
}

async function clearWidgetCache() {
  localStorage.clear();
  lastAccessToken = null;
  callApiBtn.disabled = true;
  setStatus("Widget cache cleared.");
  log("localStorage cleared");
}

silentAuthBtn.addEventListener("click", getTokenSilently);
callApiBtn.addEventListener("click", callProtectedApi);
clearCacheBtn.addEventListener("click", clearWidgetCache);

init().catch(err => {
  setStatus("Widget init failed: " + err.message);
  log("Widget init failed", { message: err.message, stack: err.stack });
});
