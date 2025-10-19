const els = {
  navGuest: document.getElementById("nav-guest"),
  navAuthed: document.getElementById("nav-authed"),
  guestHero: document.getElementById("guest-hero"),
  authedHero: document.getElementById("authed-hero"),
  nextSteps: document.getElementById("next-steps"),
  claimsPre: document.getElementById("claims"),
  tokenPre: document.getElementById("token"),
  signInBtn: document.getElementById("signInBtn"),
  signUpBtn: document.getElementById("signUpBtn"),
  signOutLink: document.getElementById("signOutLink"),
  avatar: document.getElementById("avatar"),
  fullName: document.getElementById("fullName"),
  getTokenBtn: document.getElementById("getTokenBtn"),
}

function safeSetText(el, text) {
  if (el) el.textContent = text
}
function safeSetSrc(el, src, alt = "") {
  if (!el) return
  if (src) {
    el.src = src
    el.alt = alt || ""
  } else {
    el.removeAttribute("src")
  }
}

function setAuthedUI(on, claims) {
  // guard everything with optional chaining to avoid null errors
  if (on) {
    els.navGuest?.classList.add("hidden")
    els.navAuthed?.classList.remove("hidden")
    els.guestHero?.classList.add("hidden")
    els.authedHero?.classList.remove("hidden")
    els.nextSteps?.classList.remove("hidden")

    const name =
      [claims?.given_name, claims?.family_name].filter(Boolean).join(" ") ||
      claims?.name ||
      "Signed in"
    safeSetText(els.fullName, name)
    safeSetSrc(els.avatar, claims?.picture, name)
  } else {
    els.navGuest?.classList.remove("hidden")
    els.navAuthed?.classList.add("hidden")
    els.guestHero?.classList.remove("hidden")
    els.authedHero?.classList.add("hidden")
    els.nextSteps?.classList.add("hidden")
    safeSetText(els.claimsPre, "{}")
    safeSetText(els.tokenPre, '(click "Get access token")')
  }
}

// --- Startup: restore session if present ---
async function bootstrap() {
  try {
    const res = await window.kindeAuth.getSession()
    if (res?.ok && res.signedIn) {
      if (els.claimsPre)
        els.claimsPre.textContent = JSON.stringify(res.claims || {}, null, 2)
      setAuthedUI(true, res.claims)
    } else {
      setAuthedUI(false)
    }
  } catch {
    setAuthedUI(false)
  }
}

// Wire buttons (unchanged, but safe to keep)
els.signInBtn?.addEventListener("click", async () => {
  safeSetText(els.claimsPre, "...")
  const res = await window.kindeAuth.login()
  if (!res.ok) {
    safeSetText(els.claimsPre, "Login failed: " + res.error)
    setAuthedUI(false)
  } else {
    if (els.claimsPre)
      els.claimsPre.textContent = JSON.stringify(res.claims, null, 2)
    setAuthedUI(true, res.claims)
  }
})

els.signUpBtn?.addEventListener("click", async () => {
  els.signInBtn?.click()
})

els.getTokenBtn?.addEventListener("click", async () => {
  safeSetText(els.tokenPre, "...")
  const res = await window.kindeAuth.getAccessToken()
  safeSetText(
    els.tokenPre,
    res.ok ? res.access_token || "(no token)" : "Error: " + res.error
  )
})

els.signOutLink?.addEventListener("click", async (e) => {
  e.preventDefault()
  await window.kindeAuth.logout()
  setAuthedUI(false)
})

// Ensure DOM is ready, then bootstrap
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootstrap)
} else {
  bootstrap()
}