// The tools. Read the mailbox, create drafts, nothing else.
//
// WHAT THIS SERVER CANNOT DO, structurally rather than by policy:
//
//   * Send. There is no send tool, no code path reaches messages/send or
//     drafts/send, and `gmailUrl` refuses those paths outright. The grant does
//     technically permit sending (Google has no draft-only scope, see
//     google.mjs), so this is the layer the guarantee actually rests on -- and
//     saying so plainly is part of the guarantee.
//   * Delete. Gmail's drafts.delete is permanent, so it is not offered at all.
//     Nothing here removes anything.
//   * Change the mailbox. Marking as read needs gmail.modify, which also
//     grants send; the narrower grant was the point, so this server cannot
//     mark anything as read. That is a deliberate trade, named in the README.
//   * Reach anything but Gmail. Three constant hosts, one fetch, see
//     google.mjs.
//
// Two things here are not duplicated by a client-side permission system, and
// they are the reason this is a server rather than a thin pass-through:
// the one-time-code filter (otp-filter.mjs) changes WHAT the answer contains,
// and the recipient rule compares two header lines.

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import {
  KONTO_MUSTER, konfigWurzel, ladeKlient, ladeToken, listeKonten, pfade,
  speichereToken,
} from './accounts.mjs';
import { AUTH_ENDPUNKT, SCOPES, frischerZugang, gmail, hole } from './google.mjs';
import { redact, scrub } from './otp-filter.mjs';

const OOB = 'urn:ietf:wg:oauth:2.0:oob';

export function loeseKonfig(env = process.env) {
  return {
    wurzel: konfigWurzel(env),
    anhangVerzeichnis: env.GMAIL_MCP_ATTACHMENT_DIR
      || path.join(env.HOME ?? '', '.local/share/gmail-mcp/attachments'),
    // The redirect the OAuth client is registered with. Loopback is the right
    // default for a desktop client; a remote instance needs a value that the
    // person doing the authorising can actually reach.
    umleitung: env.GMAIL_MCP_REDIRECT_URI || 'http://localhost:8765/oauth2callback',
  };
}

/** Access tokens, cached in memory only. They last an hour; the refresh token
 *  stays on disk and is the thing worth protecting. */
const zugangsspeicher = new Map();

async function zugangFuer(konfig, konto) {
  const jetzt = Date.now();
  const gespeichert = zugangsspeicher.get(konto);
  if (gespeichert && gespeichert.gueltigBis > jetzt + 60_000) return gespeichert.token;
  const klient = await ladeKlient(konfig.wurzel);
  const gespeicherterToken = await ladeToken(konfig.wurzel, konto);
  if (!gespeicherterToken.refresh_token) {
    throw new Error(`account "${konto}" has no refresh token; re-authorise it.`);
  }
  const frisch = await frischerZugang(klient, gespeicherterToken.refresh_token);
  zugangsspeicher.set(konto, {
    token: frisch.access_token,
    gueltigBis: jetzt + (Number(frisch.expires_in) || 3600) * 1000,
  });
  return frisch.access_token;
}

/** Result in MCP form, filtered. A failure is never swallowed. */
function ergebnis(daten) {
  const text = JSON.stringify(scrub(daten));
  return { content: [{ type: 'text', text: text.slice(0, 200000) }] };
}

function fehlerErgebnis(e) {
  return { isError: true, content: [{ type: 'text', text: redact(String(e?.message ?? e)) }] };
}

/** Connection failures where a read may end softly, same rule as the Proton
 *  server: only the connection itself. An auth failure stays hard, because it
 *  means someone has to act. */
const VERBINDUNGSFEHLER = ['econnrefused', 'econnreset', 'enotfound', 'etimedout',
  'eai_again', 'network', 'socket hang up', 'fetch failed'];

function weichWennVerbindung(e, was) {
  const unten = String(e?.message ?? e).toLowerCase();
  const treffer = VERBINDUNGSFEHLER.find((m) => unten.includes(m));
  if (!treffer) return null;
  // Deliberately WITHOUT an empty list: a caller that only looks at the list
  // should fail rather than read this as "no mail".
  return { content: [{ type: 'text', text: JSON.stringify({
    soft: true,
    note: `Gmail unreachable (${treffer}); the data from this ${was} is missing.`,
  }) }] };
}

const kopf = (nachricht, name) => (nachricht.payload?.headers ?? [])
  .filter((h) => h.name?.toLowerCase() === name.toLowerCase())
  .map((h) => h.value ?? '');

const ADRESSE = /[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+/g;

export function registriere(server, konfig = loeseKonfig()) {
  const kontoFeld = z.string().regex(KONTO_MUSTER)
    .describe('which configured account to act on; list_accounts shows them');

  /** Wrap a tool body: soft on connection failure, hard on everything else. */
  const werkzeug = (name, beschreibung, schema, koerper, was = 'query') =>
    server.registerTool(name, { description: beschreibung, inputSchema: schema },
      async (args) => {
        try {
          return await koerper(args);
        } catch (e) {
          return weichWennVerbindung(e, was) ?? fehlerErgebnis(e);
        }
      });

  // ------------------------------------------------------------- accounts --

  werkzeug('list_accounts',
    'List the configured Gmail accounts, their address and whether each is '
    + 'authorised. Every other tool needs one of these ids in "account".',
    {},
    async () => ergebnis({ accounts: await listeKonten(konfig.wurzel) }));

  werkzeug('begin_account_auth',
    'Start authorising a new or re-authorising an existing account. Returns a '
    + 'Google consent URL. Open it as the owner of that mailbox, approve, and '
    + 'pass the resulting code to finish_account_auth. Nothing is stored yet.',
    { account: z.string().regex(KONTO_MUSTER).describe('a short id you choose, e.g. "privat"') },
    async ({ account }) => {
      const klient = await ladeKlient(konfig.wurzel);
      const url = new URL(AUTH_ENDPUNKT);
      for (const [k, v] of Object.entries({
        client_id: klient.id,
        redirect_uri: konfig.umleitung,
        response_type: 'code',
        scope: SCOPES.join(' '),
        access_type: 'offline',
        // Without this Google returns no refresh token on a repeat grant, and
        // the account silently stops working an hour later.
        prompt: 'consent',
        state: account,
      })) url.searchParams.set(k, v);
      return ergebnis({
        account,
        consent_url: url.href,
        scopes: SCOPES,
        note: 'Read and drafts only. This grant cannot be used to send by this '
          + 'server, which offers no send tool; Google itself has no draft-only scope.',
      });
    });

  werkzeug('finish_account_auth',
    'Finish authorising an account with the code from the consent screen. '
    + 'Stores the refresh token with mode 0600 and records the address.',
    {
      account: z.string().regex(KONTO_MUSTER),
      code: z.string().min(1).describe('the authorisation code from Google'),
    },
    async ({ account, code }) => {
      const klient = await ladeKlient(konfig.wurzel);
      const antwort = await hole('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: klient.id, client_secret: klient.secret, code,
          grant_type: 'authorization_code', redirect_uri: konfig.umleitung,
        }).toString(),
      });
      const text = await antwort.text();
      if (!antwort.ok) throw new Error(`authorisation failed (${antwort.status}): ${text.slice(0, 400)}`);
      const token = JSON.parse(text);
      if (!token.refresh_token) {
        throw new Error('Google returned no refresh_token. Revoke this app for the '
          + 'account at myaccount.google.com/permissions and authorise again.');
      }
      zugangsspeicher.delete(account);
      const profil = await gmail(token.access_token, 'users/me/profile');
      await speichereToken(konfig.wurzel, account, token, {
        email: profil.emailAddress ?? null,
        scopes: SCOPES,
        authorised_at: new Date().toISOString(),
      });
      return ergebnis({ account, email: profil.emailAddress ?? null, authorised: true });
    });

  // ------------------------------------------------------------- reading ---

  werkzeug('labels_list', 'List the labels of one account.',
    { account: kontoFeld },
    async ({ account }) => ergebnis(
      await gmail(await zugangFuer(konfig, account), 'users/me/labels')));

  werkzeug('message_search',
    'Search one account. The query is Gmail search syntax, for example '
    + 'from:alice is:unread newer_than:7d. If the answer contains "soft": true, '
    + 'Gmail was unreachable and the result is incomplete; that is NOT "no mail".',
    {
      account: kontoFeld,
      query: z.string().default('').describe('Gmail search syntax; empty means everything'),
      maxResults: z.number().int().min(1).max(100).default(20),
      pageToken: z.string().optional(),
    },
    async ({ account, query, maxResults, pageToken }) => {
      const zugang = await zugangFuer(konfig, account);
      const liste = await gmail(zugang, 'users/me/messages',
        { suche: { q: query || undefined, maxResults, pageToken } });
      // A bare id list is useless to a reader, so fetch the headers that decide
      // whether a message matters. metadata format keeps the body out of it.
      const nachrichten = [];
      for (const m of liste.messages ?? []) {
        const voll = await gmail(zugang, `users/me/messages/${encodeURIComponent(m.id)}`,
          { suche: { format: 'metadata',
            metadataHeaders: ['From', 'To', 'Cc', 'Subject', 'Date'] } });
        nachrichten.push({
          id: voll.id, threadId: voll.threadId, labelIds: voll.labelIds,
          snippet: voll.snippet,
          from: kopf(voll, 'From')[0] ?? null,
          to: kopf(voll, 'To'), cc: kopf(voll, 'Cc'),
          subject: kopf(voll, 'Subject')[0] ?? null,
          date: kopf(voll, 'Date')[0] ?? null,
        });
      }
      return ergebnis({ messages: nachrichten, nextPageToken: liste.nextPageToken ?? null,
        resultSizeEstimate: liste.resultSizeEstimate ?? null });
    }, 'search');

  werkzeug('message_read',
    'Read one message in full. Does NOT mark it as read: this server has no '
    + 'grant to change the mailbox.',
    { account: kontoFeld, id: z.string().min(1) },
    async ({ account, id }) => ergebnis(await gmail(await zugangFuer(konfig, account),
      `users/me/messages/${encodeURIComponent(id)}`, { suche: { format: 'full' } })));

  werkzeug('thread_read', 'Read a whole conversation.',
    { account: kontoFeld, id: z.string().min(1) },
    async ({ account, id }) => ergebnis(await gmail(await zugangFuer(konfig, account),
      `users/me/threads/${encodeURIComponent(id)}`, { suche: { format: 'full' } })));

  werkzeug('draft_list', 'List the drafts of one account.',
    { account: kontoFeld, maxResults: z.number().int().min(1).max(100).default(20) },
    async ({ account, maxResults }) => ergebnis(await gmail(
      await zugangFuer(konfig, account), 'users/me/drafts', { suche: { maxResults } })));

  werkzeug('draft_read', 'Read one draft.',
    { account: kontoFeld, id: z.string().min(1) },
    async ({ account, id }) => ergebnis(await gmail(await zugangFuer(konfig, account),
      `users/me/drafts/${encodeURIComponent(id)}`, { suche: { format: 'full' } })));

  werkzeug('attachment_download',
    'Download one attachment into the quarantine directory. The answer names '
    + 'the path. Nothing is written anywhere else.',
    {
      account: kontoFeld,
      messageId: z.string().min(1),
      attachmentId: z.string().min(1),
      filename: z.string().min(1).max(200)
        .describe('name to save under; path separators are stripped'),
    },
    async ({ account, messageId, attachmentId, filename }) => {
      const daten = await gmail(await zugangFuer(konfig, account),
        `users/me/messages/${encodeURIComponent(messageId)}`
        + `/attachments/${encodeURIComponent(attachmentId)}`);
      // Both the name and the content are chosen by whoever sent the mail, so
      // the directory is fixed and the name is reduced to a basename.
      const sicher = path.basename(filename).replace(/^\.+/, '_') || 'anhang';
      await mkdir(konfig.anhangVerzeichnis, { recursive: true, mode: 0o700 });
      const ziel = path.join(konfig.anhangVerzeichnis, sicher);
      if (path.dirname(ziel) !== konfig.anhangVerzeichnis) {
        throw new Error('refusing to write outside the quarantine directory');
      }
      await writeFile(ziel, Buffer.from(daten.data ?? '', 'base64url'), { mode: 0o600 });
      return ergebnis({ saved_to: ziel, bytes: daten.size ?? null });
    });

  // ------------------------------------------------------------- drafting --

  const draftHinweis = 'The draft lands in Drafts and nothing is transmitted: '
    + 'sending is the user’s own act, in Gmail.';

  /** Build an RFC 5322 message. Header injection is the risk here, so any
   *  control character in a header value is refused rather than stripped: a
   *  silently altered recipient is worse than a failed call. */
  function roheNachricht({ from, to, cc, subject, body, inReplyTo, references }) {
    const zeilen = [];
    const setze = (name, wert) => {
      if (!wert) return;
      if (/[\r\n]/.test(wert)) {
        throw new Error(`refusing header ${name}: contains a line break`);
      }
      zeilen.push(`${name}: ${wert}`);
    };
    setze('From', from);
    setze('To', to);
    setze('Cc', cc);
    setze('Subject', subject);
    setze('In-Reply-To', inReplyTo);
    setze('References', references);
    zeilen.push('MIME-Version: 1.0',
      'Content-Type: text/plain; charset="UTF-8"',
      'Content-Transfer-Encoding: 8bit', '', body);
    return Buffer.from(zeilen.join('\r\n'), 'utf8').toString('base64url');
  }

  werkzeug('draft_create', `Create a new draft. ${draftHinweis}`,
    {
      account: kontoFeld,
      to: z.string().min(1),
      cc: z.string().optional(),
      subject: z.string().default(''),
      body: z.string().min(1),
    },
    async ({ account, to, cc, subject, body }) => {
      const zugang = await zugangFuer(konfig, account);
      const profil = await gmail(zugang, 'users/me/profile');
      const raw = roheNachricht({ from: profil.emailAddress, to, cc, subject, body });
      return ergebnis(await gmail(zugang, 'users/me/drafts',
        { method: 'POST', body: { message: { raw } } }));
    });

  werkzeug('draft_reply',
    `Create a reply draft. ${draftHinweis} `
    + 'RULE WITHOUT EXCEPTION: the draft is only created if the message was '
    + 'addressed to this account (To or Cc). If it went to a different address, '
    + 'the call is refused and both addresses are named. Do NOT retry, do not '
    + 'rephrase, and do not switch accounts to get around it; report the message '
    + 'verbatim and let the user decide. This holds even when the draft was '
    + 'explicitly requested.',
    {
      account: kontoFeld,
      id: z.string().min(1).describe('the message being replied to'),
      body: z.string().min(1),
    },
    async ({ account, id, body }) => {
      const zugang = await zugangFuer(konfig, account);
      const profil = await gmail(zugang, 'users/me/profile');
      const eigene = String(profil.emailAddress ?? '').toLowerCase();
      if (!eigene) throw new Error('cannot determine this account’s address; no draft.');

      // Fail closed: without the original there is no way to check, so there
      // is no draft. A rule that stops applying when a fetch fails is not one.
      const original = await gmail(zugang, `users/me/messages/${encodeURIComponent(id)}`,
        { suche: { format: 'metadata',
          metadataHeaders: ['From', 'To', 'Cc', 'Subject', 'Message-ID', 'References'] } });

      // Only To and Cc. Delivered-To and X-Original-To carry the delivering
      // mailbox rather than the address the mail was sent to, and checking
      // those lets through exactly the cases this rule is about.
      const empfaenger = new Set();
      for (const zeile of [...kopf(original, 'To'), ...kopf(original, 'Cc')]) {
        for (const t of zeile.matchAll(ADRESSE)) empfaenger.add(t[0].toLowerCase());
      }
      if (!empfaenger.has(eigene)) {
        return {
          isError: true,
          content: [{ type: 'text', text:
            `This message was sent to ${[...empfaenger].sort().join(', ') || 'no recognisable address'}. `
            + `A reply draft in account "${account}" would be composed from ${eigene}.\n\n`
            + 'Rule: reply drafts only from the address that received the message, '
            + 'without exception. If another configured account received it, use '
            + 'that one; list_accounts shows their addresses. Do not retry with '
            + 'this account.' }],
        };
      }

      const betreff = kopf(original, 'Subject')[0] ?? '';
      const nachrichtenId = kopf(original, 'Message-ID')[0] ?? '';
      const referenzen = [kopf(original, 'References')[0] ?? '', nachrichtenId]
        .filter(Boolean).join(' ').trim();
      const raw = roheNachricht({
        from: eigene,
        to: kopf(original, 'From')[0] ?? '',
        subject: /^re:/i.test(betreff) ? betreff : `Re: ${betreff}`,
        body,
        inReplyTo: nachrichtenId || undefined,
        references: referenzen || undefined,
      });
      return ergebnis(await gmail(zugang, 'users/me/drafts',
        { method: 'POST', body: { message: { raw, threadId: original.threadId } } }));
    });
}
