// Contract: how far this server can reach.
//
// The implementation this replaces had a tool that POSTed to a URL taken out
// of a mail header, and requested full Gmail, full Drive, Sheets, Docs and
// Calendar. These cases exist so that neither can come back unnoticed.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import { REPO, rufe, werkzeug, antwortZu, daten, inhalt } from './helpers.mjs';
import { SCOPES, gmailUrl, hole } from '../src/google.mjs';

// --------------------------------------------------------------- scopes ----

test('The grant is read plus drafts, and nothing else', () => {
  assert.deepEqual([...SCOPES].sort(), [
    'https://www.googleapis.com/auth/gmail.compose',
    'https://www.googleapis.com/auth/gmail.readonly',
  ]);
  for (const verboten of ['mail.google.com', 'gmail.send', 'gmail.modify',
    'gmail.settings', 'auth/drive', 'spreadsheets', 'documents', 'calendar']) {
    assert.ok(!SCOPES.some((s) => s.includes(verboten)),
      `scope ${verboten} must not be requested`);
  }
});

// ------------------------------------------------------- outbound hosts ----

test('The source tree contains no URL outside the three Google hosts', () => {
  // The check that would have caught the unsubscribe hole by reading the code
  // rather than by guessing what a tool does.
  const ERLAUBT = [
    'https://gmail.googleapis.com/gmail/v1/',
    'https://oauth2.googleapis.com/token',
    'https://accounts.google.com/o/oauth2/v2/auth',
    'https://gmail.googleapis.com',
    'https://oauth2.googleapis.com',
    'https://accounts.google.com',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.compose',
    // The readiness line of the HTTP entry point, describing the LOCAL bind.
    // It is a log message, never a request target, and `hole` would refuse it.
    'http://${ADDRESS}:${port}/mcp',
    // The OAuth redirect fallback. It is handed TO Google as a parameter and
    // is never a request target of this server. The real value comes from the
    // client file; this applies only when that file names none.
    'http://localhost',
  ];
  const gefunden = new Set();
  for (const datei of fs.readdirSync(path.join(REPO, 'src'))) {
    if (!datei.endsWith('.mjs')) continue;
    const text = fs.readFileSync(path.join(REPO, 'src', datei), 'utf8');
    for (const zeile of text.split('\n')) {
      // Comments describe the hole that is being closed and name example
      // hosts; only code counts.
      if (/^\s*(\/\/|\*)/.test(zeile)) continue;
      for (const t of zeile.matchAll(/https?:\/\/[^\s'"`)]+/g)) {
        gefunden.add(t[0].replace(/[.,;]$/, ''));
      }
    }
  }
  for (const u of gefunden) {
    assert.ok(ERLAUBT.some((e) => u === e || u.startsWith(e)),
      `unexpected URL in the source: ${u}`);
  }
});

test('fetch is named in exactly one file, and it is the one with the guard', () => {
  // Measured rather than assumed: there is no literal `fetch(` call anywhere.
  // `hole` receives it as a default parameter and calls it through `holen`,
  // which is also what makes it substitutable in tests without giving the
  // production build a switch. The invariant that matters is therefore not
  // "one call site" but "the name appears only in the file that checks the
  // origin first".
  const dateien = new Set();
  for (const datei of fs.readdirSync(path.join(REPO, 'src'))) {
    if (!datei.endsWith('.mjs')) continue;
    const text = fs.readFileSync(path.join(REPO, 'src', datei), 'utf8');
    for (const zeile of text.split('\n')) {
      if (/^\s*(\/\/|\*)/.test(zeile)) continue;
      // Strip string literals first: 'fetch failed' is an error message in a
      // list of connection failures, not a call. A scan that cannot tell the
      // two apart would either miss real calls or cry wolf, and a test that
      // cries wolf gets switched off.
      const ohneText = zeile.replace(/'[^']*'|"[^"]*"|`[^`]*`/g, "''");
      if (/\bfetch\b/.test(ohneText)) dateien.add(datei);
    }
  }
  assert.deepEqual([...dateien], ['google.mjs'],
    `fetch is named in: ${[...dateien].join(', ')}`);
});

test('hole refuses any origin that is not one of the three', async () => {
  for (const u of ['https://evil.example/x', 'http://127.0.0.1:5432/',
    'http://169.254.169.254/latest/meta-data/', 'https://gmail.googleapis.com.evil.example/']) {
    await assert.rejects(() => hole(u, {}, async () => { throw new Error('reached the network'); }),
      /refusing to contact/, u);
  }
});

test('A redirect is an error, not a second chance at the same hole', async () => {
  let gesehen = null;
  await hole('https://gmail.googleapis.com/gmail/v1/users/me/profile', {},
    async (_u, o) => { gesehen = o; return { ok: true, status: 200, text: async () => '{}' }; });
  assert.equal(gesehen.redirect, 'error');
});

// ------------------------------------------------------------ path guard ---

test('gmailUrl refuses every attempt to leave the Gmail API', () => {
  for (const pfad of [
    '/etc/passwd', '//evil.example/x', 'https://evil.example/x',
    'http://127.0.0.1/', '../../oauth2/v4/token',
  ]) {
    assert.throws(() => gmailUrl(pfad), /refusing/, pfad);
  }
});

test('gmailUrl refuses the send and settings paths outright', () => {
  for (const pfad of [
    'users/me/messages/send', 'users/me/drafts/abc/send', 'users/me/drafts/send',
    'users/me/settings/forwardingAddresses', 'users/me/settings/filters',
    'users/me/watch', 'users/me/stop',
  ]) {
    assert.throws(() => gmailUrl(pfad), /not reachable/, pfad);
  }
});

test('gmailUrl builds the ordinary paths', () => {
  assert.equal(gmailUrl('users/me/labels').href,
    'https://gmail.googleapis.com/gmail/v1/users/me/labels');
  assert.equal(gmailUrl('users/me/messages', { q: 'from:a', maxResults: 5 }).href,
    'https://gmail.googleapis.com/gmail/v1/users/me/messages?q=from%3Aa&maxResults=5');
});

// ------------------------------------------------------------- the tools ---

test('The tool list contains no way to send, delete or share', async () => {
  const { antworten } = await rufe([
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }]);
  const namen = antwortZu(antworten, 2).result.tools.map((t) => t.name).sort();
  for (const verboten of ['send', 'delete', 'trash', 'share', 'unsubscribe',
    'block', 'drive', 'sheets', 'docs', 'calendar', 'event', 'label_']) {
    assert.ok(!namen.some((n) => n.includes(verboten)),
      `no tool may contain '${verboten}': ${namen.join(', ')}`);
  }
  assert.deepEqual(namen, [
    'attachment_download', 'begin_account_auth', 'draft_create', 'draft_list',
    'draft_read', 'draft_reply', 'finish_account_auth', 'labels_list',
    'list_accounts', 'message_read', 'message_search', 'thread_read',
  ]);
});

test('No tool call ever reaches a send or settings endpoint', async () => {
  const AUFRUFE = [
    ['list_accounts', {}],
    ['labels_list', { account: 'probe' }],
    ['message_search', { account: 'probe', query: 'from:alice' }],
    ['message_read', { account: 'probe', id: 'abc123' }],
    ['thread_read', { account: 'probe', id: 'abc123' }],
    ['draft_list', { account: 'probe' }],
    ['draft_read', { account: 'probe', id: 'r1' }],
    ['draft_create', { account: 'probe', to: 'a@x.org', subject: 'S', body: 'T' }],
  ];
  for (const [name, args] of AUFRUFE) {
    const { rufe: netz } = await rufe([werkzeug(name, args)]);
    for (const r of netz) {
      assert.ok(!/\/send(\?|$)/.test(r.url), `${name} reached ${r.url}`);
      assert.ok(!r.url.includes('/settings/'), `${name} reached ${r.url}`);
      assert.ok(r.url.startsWith('https://gmail.googleapis.com/')
        || r.url.startsWith('https://oauth2.googleapis.com/'),
        `${name} reached ${r.url}`);
    }
  }
});
