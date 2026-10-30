// lockhub mobile facade. Plain browser JavaScript, no build step.
//
// The device's keys never leave it: a WebAuthn credential (ES256, user
// verification) signs each decision, and a non-extractable X25519 key
// (WebCrypto, kept in IndexedDB) opens the clear screens a lock sealed to
// this device. Untrusted text (everything from a lock or an agent) is only
// ever set with textContent.
"use strict";

const enc = new TextEncoder();
const dec = new TextDecoder();
const $ = (id) => document.getElementById(id);

// ---- encoding ---------------------------------------------------------

function b64u(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64u(s) {
  const t = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(t.length);
  for (let i = 0; i < t.length; i++) out[i] = t.charCodeAt(i);
  return out;
}
function hex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}
function concat(...parts) {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }

// canonical is RFC 8785 for the flat objects this app signs or hashes:
// members sorted by UTF-16 code units, strings as JSON.stringify writes
// them (the same escapes), integers as decimals.
function canonical(v) {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isInteger(v)) throw new Error("canonical: only integers");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}

// ---- local key store (IndexedDB) -------------------------------------

function db() {
  return new Promise((ok, ko) => {
    const r = indexedDB.open("lockhub", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("keys");
    r.onsuccess = () => ok(r.result);
    r.onerror = () => ko(r.error);
  });
}
async function kv(mode, fn) {
  const d = await db();
  return new Promise((ok, ko) => {
    const tx = d.transaction("keys", mode);
    const req = fn(tx.objectStore("keys"));
    tx.oncomplete = () => ok(req && req.result);
    tx.onerror = () => ko(tx.error);
  });
}
const getKey = (k) => kv("readonly", (s) => s.get(k));
const putKey = (k, v) => kv("readwrite", (s) => s.put(v, k));

// ---- API ---------------------------------------------------------------

async function api(method, path, body) {
  const opt = { method, credentials: "same-origin", headers: {} };
  if (method === "POST") {
    opt.headers["Content-Type"] = "application/json";
    opt.headers["X-Lockhub"] = "1";
    opt.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error(j.message || "error " + r.status);
    e.kind = j.error;
    e.status = r.status;
    throw e;
  }
  return j;
}

function status(msg) { $("status").textContent = msg || ""; }

function show(section) {
  for (const id of ["pair", "login", "queue"]) $(id).hidden = id !== section;
}

// ---- device record and fingerprint (lockkit ticket.Device) ------------

async function deviceID(cred) { return "webauthn:" + hex((await sha256(cred)).slice(0, 16)); }

async function fingerprint(rec) {
  const h = hex((await sha256(enc.encode(canonical(rec)))).slice(0, 10));
  return h.match(/.{4}/g).join(" ");
}

// The P-256 point of an SPKI (getPublicKey): its last 65 bytes.
function spkiPoint(spki) {
  const b = new Uint8Array(spki);
  const p = b.slice(b.length - 65);
  if (p[0] !== 4) throw new Error("not an uncompressed P-256 key");
  return p;
}

// ---- pairing ------------------------------------------------------------

async function pair(code) {
  status("Pairing…");
  const begin = await api("POST", "/m/v1/pair/begin", { code });
  const o = begin.options;
  o.challenge = unb64u(o.challenge);
  o.user.id = unb64u(o.user.id);
  if (o.excludeCredentials) o.excludeCredentials = o.excludeCredentials.map((c) => ({ ...c, id: unb64u(c.id) }));
  const cred = await navigator.credentials.create({ publicKey: o });
  const resp = cred.response;
  const x = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const xpub = new Uint8Array(await crypto.subtle.exportKey("raw", x.publicKey));
  const credential = {
    id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64u(resp.clientDataJSON), attestationObject: b64u(resp.attestationObject) },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  };
  const fin = await api("POST", "/m/v1/pair/finish", { pairing: begin.pairing, credential, x25519: b64u(xpub) });
  // The fingerprint this phone computes from its own keys, not the hub's.
  const raw = new Uint8Array(cred.rawId);
  const rec = {
    v: 1, id: await deviceID(raw), credential: b64u(raw), name: begin.name,
    rp_id: location.hostname, origin: location.origin,
    es256: b64u(spkiPoint(resp.getPublicKey())), x25519: b64u(xpub),
  };
  const fp = await fingerprint(rec);
  if (fp !== fin.fingerprint) throw new Error("the hub registered another device record than this phone's: do not confirm");
  // Pending until it signs in once (the host confirmed it): a declined
  // pairing does not replace a working one.
  await putKey("pending", { rec, x25519: x.privateKey });
  $("fp").textContent = fp;
  $("pair-done").hidden = false;
  status("Registered. Confirm on the host, then sign in.");
}

// ---- login --------------------------------------------------------------

async function assert(challenge, rec) {
  const a = await navigator.credentials.get({
    publicKey: {
      challenge, rpId: rec.rp_id, userVerification: "required", timeout: 120000,
      allowCredentials: [{ type: "public-key", id: unb64u(rec.credential) }],
    },
  });
  return {
    device: rec.id, auth_data: b64u(a.response.authenticatorData),
    client_data: b64u(a.response.clientDataJSON), sig: b64u(a.response.signature),
  };
}

// loginWith signs in as dev. The challenge is computed here from the
// hub's nonce: a challenge the hub chose whole could be a decision's.
async function loginWith(dev) {
  const b = await api("POST", "/m/v1/login/begin", {});
  const ch = await sha256(concat(enc.encode("lockhub/mobile-login/v1"), [0], unb64u(b.nonce)));
  const assertion = await assert(ch, dev.rec);
  return api("POST", "/m/v1/login/finish", { id: b.id, assertion });
}

async function login() {
  status("Signing in…");
  let r;
  const pending = await getKey("pending");
  if (pending) {
    try {
      r = await loginWith(pending);
      await putKey("device", pending);
      await kv("readwrite", (s) => s.delete("pending"));
    } catch (e) {
      if (!(await getKey("device"))) throw e;
    }
  }
  if (!r) {
    const dev = await getKey("device");
    if (!dev) { show("pair"); return; }
    r = await loginWith(dev);
  }
  $("who").textContent = r.name;
  status("");
  show("queue");
  poll();
}

// ---- sealed clear screen (lockkit ticket.SealAlgGCM) -------------------

async function openClear(t, dev) {
  const mine = (t.pii.sealed_for || []).find((b) => b.device === dev.rec.id);
  if (!mine || mine.box.alg !== "x25519-hkdf-sha256-aes256gcm") return null;
  const epk = unb64u(mine.box.epk);
  const peer = await crypto.subtle.importKey("raw", epk, { name: "X25519" }, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer }, dev.x25519, 256));
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: concat(epk, unb64u(dev.rec.x25519)), info: enc.encode("lockkit/sealed-gcm/v1") },
    ikm, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
  const aad = concat(enc.encode("lockkit/clear-screen/v1"), [0], enc.encode(t.id), [0], enc.encode(dev.rec.id));
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(mine.box.nonce), additionalData: aad }, key, unb64u(mine.box.ct));
  return JSON.parse(dec.decode(pt));
}

// ---- queue --------------------------------------------------------------

let version = 0;
let polling = false;

async function poll() {
  if (polling) return;
  polling = true;
  try {
    for (;;) {
      const q = await api("GET", "/m/v1/queue?since=" + version + "&wait=25");
      version = q.version;
      await render(q.tickets);
    }
  } catch (e) {
    if (e.status === 401) { show("login"); status(e.message); } else { status("Disconnected: " + e.message); setTimeout(poll, 5000); }
  } finally {
    polling = false;
  }
}

function lines(el, xs) { el.textContent = (xs || []).join("\n"); }

async function render(items) {
  const dev = (await getKey("device")) || (await getKey("pending"));
  const ul = $("tickets");
  ul.replaceChildren();
  $("count").textContent = items.length ? "(" + items.length + ")" : "";
  for (const it of items) {
    const t = JSON.parse(it.ticket);
    // What is shown and signed is the lock's signed ticket, not the hub's
    // labels: an item whose labels disagree with it is not shown.
    if (it.id !== t.id || it.instance !== t.source.instance || it.risk !== t.risk) continue;
    const li = $("ticket-tpl").content.firstElementChild.cloneNode(true);
    const q = (c) => li.querySelector(c);
    if (t.screen.red || t.flags.production) li.classList.add("red");
    q(".risk").textContent = t.risk + (t.flags.production ? " · production" : "");
    q(".where").textContent = t.source.lock + " / " + t.source.instance;
    q(".header").textContent = t.screen.header;
    q(".requester").textContent = "requested by unverified: " + t.requester.agent;
    q(".note").textContent = t.screen.note;
    lines(q(".body"), t.screen.body);
    for (const w of t.screen.warnings || []) { const x = document.createElement("li"); x.textContent = w; q(".warnings").append(x); }
    try {
      const clear = await openClear(t, dev);
      if (clear) { lines(q(".clear-body"), [clear.header, clear.note, ...clear.body, ...clear.warnings].filter(Boolean)); q(".clear").hidden = false; }
    } catch (e) { q(".why").textContent = "The clear values did not open on this phone."; }
    if (!it.answerable) { q(".answer").hidden = true; q(".why").textContent = it.why; }
    if (t.flags.production && t.flags.retype) q(".retype-l").hidden = false;
    q(".approve").onclick = () => answer(it, t, true, li);
    q(".deny").onclick = () => answer(it, t, false, li);
    ul.append(li);
  }
}

// checkStatement refuses to sign anything but the answer the human gave,
// on the ticket this phone shows: the hub only picks the nonce and time.
async function checkStatement(st, it, t, approve, reason, dev) {
  const want = {
    v: 1, ticket: t.id, instance: t.source.instance, key_id: t.source.key_id, plan_hash: t.plan_hash,
    decision: approve ? "approved" : "denied", reason, approver: dev.rec.id, display: dev.rec.name,
    facade: "mobile", device: dev.rec.id,
    ticket_hash: "sha256:" + hex(await sha256(enc.encode(it.ticket))),
  };
  for (const [k, v] of Object.entries(want)) {
    if (st[k] !== v) throw new Error("the hub asked to sign another " + k + ": refused");
  }
  const keys = Object.keys(st).sort().join(",");
  if (keys !== "approver,at,decision,device,display,facade,hub_key_id,instance,key_id,nonce,plan_hash,reason,ticket,ticket_hash,v") {
    throw new Error("the hub asked to sign unexpected fields: refused");
  }
  const at = Date.parse(st.at);
  if (!(Math.abs(Date.now() - at) < 2 * 60 * 1000)) throw new Error("the hub's time is off: refused");
  return sha256(concat(enc.encode("lockkit/device-decision/v1"), [0], enc.encode(canonical(st))));
}

async function answer(it, t, approve, li) {
  const dev = await getKey("device");
  const reason = li.querySelector(".reason").value;
  const retype = li.querySelector(".retype").value;
  try {
    status("Preparing…");
    const p = await api("POST", "/m/v1/tickets/" + encodeURIComponent(it.instance) + "/" + encodeURIComponent(it.id) + "/prepare", { approve, reason });
    const ch = await checkStatement(p.statement, it, t, approve, reason, dev);
    if (b64u(ch) !== p.challenge) throw new Error("the hub's challenge differs from this phone's: refused");
    const assertion = await assert(ch, dev.rec);
    await api("POST", "/m/v1/tickets/" + encodeURIComponent(it.instance) + "/" + encodeURIComponent(it.id) + "/decide", { draft: p.draft, retype, assertion });
    status(approve ? "Approved." : "Denied.");
  } catch (e) {
    status(e.message);
  }
}

// ---- start ----------------------------------------------------------------

async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
  $("pair-form").onsubmit = (e) => { e.preventDefault(); pair($("code").value).catch((x) => status(x.message)); };
  $("login-btn").onclick = () => login().catch((x) => status(x.message));
  $("logout").onclick = () => api("POST", "/m/v1/logout").then(() => { show("login"); }).catch((x) => status(x.message));
  window.addEventListener("hashchange", route);
  route();
}

async function route() {
  if (location.hash === "#pair" || !((await getKey("device")) || (await getKey("pending")))) { show("pair"); return; }
  show("login");
  // A session may still be valid: try the queue first.
  api("GET", "/m/v1/queue?since=0").then(() => { show("queue"); poll(); }).catch(() => {});
}

window.lockhub = { canonical, b64u, unb64u, hex, sha256, openClear, checkStatement };
start();
