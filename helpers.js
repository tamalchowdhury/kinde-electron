const crypto = require("crypto")

function base64urlencode(buf) {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "")
}

function generateVerifier() {
  return base64urlencode(crypto.randomBytes(32))
}
function challengeFromVerifier(v) {
  return base64urlencode(crypto.createHash("sha256").update(v).digest())
}

function randomState(len = 12) {
  return crypto
    .randomBytes(Math.ceil((len * 3) / 4))
    .toString("base64url")
    .slice(0, len)
}

// Minimal JWT decode (no signature verification)
function decodeIdToken(idToken) {
  try {
    const [, payload] = idToken.split(".")
    const pad = (s) => s + "=".repeat((4 - (s.length % 4)) % 4)
    const json = Buffer.from(
      pad(payload).replace(/-/g, "+").replace(/_/g, "/"),
      "base64"
    ).toString("utf8")
    return JSON.parse(json)
  } catch {
    return null
  }
}

function createTokenStore(storage, { serviceName, accountName, logger }) {
  const safeParse = (s) => {
    try {
      return JSON.parse(s)
    } catch {
      return null
    }
  }

  return {
    async load() {
      const s = await storage.getPassword(serviceName, accountName)
      const t = s ? safeParse(s) : null
      if (!t || typeof t.access_token !== "string") return null
      return t
    },
    async save(tokens) {
      await storage.setPassword(
        serviceName,
        accountName,
        JSON.stringify({ ...tokens })
      )
    },
    async clear() {
      try {
        await storage.deletePassword(serviceName, accountName)
      } catch (e) {
        logger?.warn?.(e)
      }
    },
    async exists() {
      return (await this.load()) !== null
    },
  }
}

module.exports = {
  generateVerifier,
  challengeFromVerifier,
  randomState,
  decodeIdToken,
  createTokenStore,
}