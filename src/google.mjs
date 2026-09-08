// Every call this server makes to the outside world.
//
// THE POINT OF THIS FILE. There are exactly three hosts, they are constants,
// and no caller can add a fourth. `googleFetch` resolves its path against a
// fixed base and then re-checks the resulting origin, so a path that tries to
// escape -- `//evil.example/`, `https://evil.example/`, a crafted message id
// with a scheme in it -- lands on the check rather than on the network. A
// contract test walks the whole source tree and fails on any URL literal that
// is not one of the three.
//
// This is not theoretical hardening. The implementation this replaces had a
// tool that POSTed to a URL taken straight out of a mail header
// (`List-Unsubscribe`), which is to say: to any address the *sender* chose,
// http:// included, with no allowlist and no guard against private ranges. On
// a machine that also runs a database and a mail catcher on the LAN, that is
// a request forgery primitive handed to anyone who can send mail.
//
// There is no fetch anywhere else in this server. Grep for it.

export const GMAIL_BASIS = 'https://gmail.googleapis.com/gmail/v1/';
export const TOKEN_ENDPUNKT = 'https://oauth2.googleapis.com/token';
export const AUTH_ENDPUNKT = 'https://accounts.google.com/o/oauth2/v2/auth';

const ERLAUBTE_URSPRUENGE = new Set([
  'https://gmail.googleapis.com',
  'https://oauth2.googleapis.com',
  'https://accounts.google.com',
]);

// Read the mailbox, and create drafts. That is the whole grant.
//
// Note what is NOT here: gmail.send, gmail.modify, gmail.settings.basic
// (which can create forwarding addresses and filters -- a mail exfiltration
// primitive), and anything touching Drive, Docs, Sheets or Calendar.
//
// An honest caveat that belongs in the code and not only in the README:
// Google has no draft-only scope. `gmail.compose` is the narrowest scope that
// can create a draft, and at the API level it also permits sending. The
// guarantee that nothing is sent therefore lives in this server -- there is no
// send tool and no code path that reaches messages/send -- exactly as it does
// for the Proton server. Claiming otherwise would be claiming something Google
// does not offer.
export const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.compose',
];

/** Paths that must never be reachable, whatever a caller passes. */
const VERBOTENE_PFADE = [
  /(^|\/)messages\/send(\?|$|\/)/i,
  /(^|\/)drafts\/[^/]+\/send(\?|$|\/)/i,
  /(^|\/)drafts\/send(\?|$|\/)/i,
  /(^|\/)settings\//i,
  /(^|\/)watch(\?|$)/i,
  /(^|\/)stop(\?|$)/i,
];

/** Build a Gmail API URL, or refuse. */
export function gmailUrl(pfad, suche = {}) {
  if (typeof pfad !== 'string' || pfad.startsWith('/') || pfad.includes(':')) {
    throw new Error(`refusing path ${JSON.stringify(pfad)}: must be relative`);
  }
  for (const muster of VERBOTENE_PFADE) {
    if (muster.test(pfad)) {
      throw new Error(`refusing path ${JSON.stringify(pfad)}: not reachable from this server`);
    }
  }
  const url = new URL(pfad, GMAIL_BASIS);
  if (url.origin !== 'https://gmail.googleapis.com'
      || !url.pathname.startsWith('/gmail/v1/')) {
    throw new Error(`refusing URL ${url.href}: outside the Gmail API`);
  }
  for (const [k, v] of Object.entries(suche)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) for (const x of v) url.searchParams.append(k, String(x));
    else url.searchParams.set(k, String(v));
  }
  return url;
}

/** The single outbound door. Nothing else in this server calls fetch. */
export async function hole(url, optionen = {}, holen = fetch) {
  const u = url instanceof URL ? url : new URL(url);
  if (!ERLAUBTE_URSPRUENGE.has(u.origin)) {
    throw new Error(`refusing to contact ${u.origin}`);
  }
  const antwort = await holen(u, {
    ...optionen,
    redirect: 'error',   // a 302 to elsewhere would be the same hole again
  });
  return antwort;
}

/** Exchange a refresh token for an access token. */
export async function frischerZugang(klient, refreshToken, holen = fetch) {
  const antwort = await hole(TOKEN_ENDPUNKT, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: klient.id,
      client_secret: klient.secret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    }).toString(),
  }, holen);
  const text = await antwort.text();
  if (!antwort.ok) {
    throw new Error(`token refresh failed (${antwort.status}): ${text.slice(0, 400)}`);
  }
  const d = JSON.parse(text);
  if (!d.access_token) throw new Error('token refresh returned no access_token');
  return d;
}

/** A Gmail API call with a bearer token. Returns parsed JSON. */
export async function gmail(zugang, pfad, { suche, method = 'GET', body } = {},
  holen = fetch) {
  const url = gmailUrl(pfad, suche);
  const kopf = { authorization: `Bearer ${zugang}` };
  let koerper;
  if (body !== undefined) {
    kopf['content-type'] = 'application/json';
    koerper = JSON.stringify(body);
  }
  const antwort = await hole(url, { method, headers: kopf, body: koerper }, holen);
  const text = await antwort.text();
  if (!antwort.ok) {
    const fehler = new Error(`Gmail API ${method} ${url.pathname} -> ${antwort.status}: `
      + text.slice(0, 600));
    fehler.status = antwort.status;
    throw fehler;
  }
  return text ? JSON.parse(text) : {};
}
