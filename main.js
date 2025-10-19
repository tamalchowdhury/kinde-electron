require("dotenv").config()

const { app, BrowserWindow, ipcMain, shell } = require("electron")
const path = require("path")
const os = require("os")
const express = require("express")
const keytar = require("keytar")

const {
  generateVerifier,
  challengeFromVerifier,
  randomState,
  decodeIdToken,
  createTokenStore,
} = require("./helpers")

// ---------- Config ----------
const CALLBACK_HOST = "127.0.0.1"
const CALLBACK_PORT = 53180
const REDIRECT_URI = `http://${CALLBACK_HOST}:${CALLBACK_PORT}/callback`

const ISSUER = process.env.KINDE_ISSUER_URL
const CLIENT_ID = process.env.KINDE_CLIENT_ID
const AUDIENCE = process.env.KINDE_AUDIENCE || ""
const SCOPES = (
  process.env.KINDE_SCOPES || "openid profile email offline"
).trim()

if (!ISSUER || !CLIENT_ID) {
  console.error("Please configure KINDE_ISSUER_URL and KINDE_CLIENT_ID in .env")
}

const tokenStore = createTokenStore(keytar, {
  serviceName: "electron-kinde-pkce-sample",
  accountName: os.userInfo().username, // or 'default'
})

// Ensure we have a fetch impl (Electron/Node 18+ has global fetch)
const fetchFn =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)))

// ---------- Small helpers ----------
function stampIssued(tokens) {
  const t = { ...tokens }
  t.issued_at = Date.now()
  if (typeof t.expires_in === "number")
    t.expires_at = t.issued_at + t.expires_in * 1000
  return t
}

async function postForm(url, data) {
  const body = new URLSearchParams(data)
  const res = await fetchFn(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`${res.status} ${text}`)
  return JSON.parse(text)
}

// ---------- OAuth helpers ----------
async function exchangeCodeForTokens({ code, codeVerifier, redirectUri }) {
  const tokenUrl = new URL("/oauth2/token", ISSUER).toString()
  const json = await postForm(tokenUrl, {
    grant_type: "authorization_code",
    code,
    client_id: CLIENT_ID,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier,
  })
  return stampIssued(json)
}

async function refreshTokens(refreshToken) {
  const tokenUrl = new URL("/oauth2/token", ISSUER).toString()
  const json = await postForm(tokenUrl, {
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
  })
  // Some providers omit refresh_token on refresh → keep the old one
  if (!json.refresh_token) json.refresh_token = refreshToken
  return stampIssued(json)
}

async function getValidAccessToken() {
  const tokens = await tokenStore.load()
  if (!tokens) return null

  const expiresAt =
    tokens.expires_at ??
    (tokens.issued_at || 0) + (tokens.expires_in || 0) * 1000

  const aboutToExpire = !expiresAt || Date.now() + 60_000 >= expiresAt // refresh when <60s left
  if (!aboutToExpire) return tokens.access_token

  if (!tokens.refresh_token) return null
  const refreshed = await refreshTokens(tokens.refresh_token)
  await tokenStore.save(refreshed)
  return refreshed.access_token
}

// ---------- Callback server (single fixed port) ----------
function listenForCallback(expectedState) {
  const appx = express()
  let server

  // Promise we resolve/reject from inside the route
  let resolveLogin, rejectLogin
  const waitForCode = new Promise((resolve, reject) => {
    resolveLogin = resolve
    rejectLogin = reject
  })

  appx.get("/callback", (req, res) => {
    const { code, state, error, error_description } = req.query

    // Validate state
    if (state !== expectedState) {
      res
        .status(400)
        .send("<h1>Invalid state</h1><p>Please try signing in again.</p>")
      try {
        server?.close()
      } catch {}
      return rejectLogin(new Error("Invalid OAuth state"))
    }

    if (error) {
      res
        .status(400)
        .send(`<h1>Login error</h1><p>${error}: ${error_description || ""}</p>`)
      try {
        server?.close()
      } catch {}
      return rejectLogin(new Error(`${error}: ${error_description || ""}`))
    }

    res.send(
      "<h1>Login successful</h1><p>You can close this window and return to the app.</p>"
    )
    try {
      server?.close()
    } catch {}
    return resolveLogin({ code: String(code), redirectUri: REDIRECT_URI })
  })

  server = appx.listen(CALLBACK_PORT, CALLBACK_HOST)
  server.on("error", (err) => {
    const msg =
      err && err.code === "EADDRINUSE"
        ? `Callback port ${CALLBACK_PORT} is already in use. Close the other process or change the port.`
        : String(err)
    try {
      server?.close()
    } catch {}
    rejectLogin(new Error(msg))
  })

  return { waitForCode }
}

// ---------- Login flow ----------
async function startLogin() {
  const codeVerifier = generateVerifier()
  const codeChallenge = challengeFromVerifier(codeVerifier)
  const state = randomState()

  // Start fixed-port server (closes itself on success/error)
  const { waitForCode } = listenForCallback(state)

  const auth = new URL("/oauth2/auth", ISSUER)
  auth.searchParams.set("client_id", CLIENT_ID)
  auth.searchParams.set("response_type", "code")
  auth.searchParams.set("redirect_uri", REDIRECT_URI)
  auth.searchParams.set("scope", SCOPES)
  auth.searchParams.set("code_challenge_method", "S256")
  auth.searchParams.set("code_challenge", codeChallenge)
  auth.searchParams.set("state", state)
  if (AUDIENCE) auth.searchParams.set("audience", AUDIENCE)

  await shell.openExternal(auth.toString())

  // Exchange the code for tokens
  const { code } = await waitForCode
  const tokens = await exchangeCodeForTokens({
    code,
    codeVerifier,
    redirectUri: REDIRECT_URI,
  })

  await tokenStore.save(tokens)
  const claims = decodeIdToken(tokens.id_token)
  return { tokens, claims }
}

async function doLogout() {
  await tokenStore.clear()
  try {
    const url = new URL("/logout", ISSUER)
    url.searchParams.set("client_id", CLIENT_ID)
    await shell.openExternal(url.toString())
  } catch {}
}

// ---------- Electron window ----------
let win
function createWindow() {
  win = new BrowserWindow({
    width: 1000,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"), // CommonJS preload
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  })
  win.loadFile(path.join(__dirname, "renderer", "index.html"))
}

app.whenReady().then(() => {
  createWindow()
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit()
})

// ---------- IPC ----------
ipcMain.handle("auth:login", async () => {
  try {
    const { claims } = await startLogin()
    return { ok: true, claims }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:getAccessToken", async () => {
  try {
    const token = await getValidAccessToken()
    return { ok: true, access_token: token }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:logout", async () => {
  try {
    await doLogout()
    return { ok: true }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})

ipcMain.handle("auth:getSession", async () => {
  try {
    const tokens = await tokenStore.load()
    if (!tokens) return { ok: true, signedIn: false }
    // Optional: ensures token freshness (ignore failure for UI)
    try {
      await getValidAccessToken()
    } catch {}
    const claims = decodeIdToken(tokens.id_token)
    return { ok: true, signedIn: true, claims }
  } catch (e) {
    return { ok: false, error: String(e) }
  }
})