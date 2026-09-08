// Contract: the protections that a permission system cannot express.
//
// A client-side permission decides WHETHER a tool runs. These decide WHAT the
// answer contains (the one-time-code filter), WHO a draft may answer (the
// recipient rule), and WHERE secrets and attacker-named files may land.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

import {
  EIGENE, KONTO, antwortZu, daten, inhalt, konfigWurzel, rufe, tmp, werkzeug,
} from './helpers.mjs';
import { pruefeRechte, schreibeGeheim } from '../src/accounts.mjs';

/** A metadata-format message as the Gmail API returns it. */
const nachricht = (an, cc = []) => ({
  body: {
    id: 'abc123', threadId: 'thr1',
    payload: { headers: [
      { name: 'From', value: 'Alice <alice@example.org>' },
      { name: 'To', value: an.join(', ') },
      ...(cc.length ? [{ name: 'Cc', value: cc.join(', ') }] : []),
      { name: 'Subject', value: 'Hallo' },
      { name: 'Message-ID', value: '<m1@example.org>' },
    ] },
  },
});

// ------------------------------------------------------- recipient rule ----

test('A reply draft is refused when the message went elsewhere', async () => {
  const { antworten, rufe: netz } = await rufe(
    [werkzeug('draft_reply', { account: KONTO, id: 'abc123', body: 'Text' })],
    { antworten: { 'messages/abc123': nachricht(['someone.else@gmail.com']) } });
  const a = antwortZu(antworten, 2);
  assert.ok(a.result?.isError, inhalt(antworten, 2).slice(0, 200));
  const text = a.result.content[0].text;
  assert.ok(text.includes('someone.else@gmail.com'), text.slice(0, 200));
  assert.ok(text.includes(EIGENE), 'both addresses must be named');
  assert.ok(!netz.some((r) => r.method === 'POST' && r.url.includes('/drafts')),
    'no draft may be created');
});

test('A reply to own mail goes through, from To and from Cc', async () => {
  for (const [an, cc] of [
    [[EIGENE], []],
    [['alice@example.org'], [EIGENE]],
    [['a@x.org', 'b@x.org', `Me <${EIGENE}>`], []],
  ]) {
    const { antworten, rufe: netz } = await rufe(
      [werkzeug('draft_reply', { account: KONTO, id: 'abc123', body: 'T' })],
      { antworten: { 'messages/abc123': nachricht(an, cc),
        'users/me/drafts': { body: { id: 'd1' } } } });
    assert.ok(!antwortZu(antworten, 2).result?.isError,
      `${an}/${cc}: ${inhalt(antworten, 2).slice(0, 200)}`);
    assert.ok(netz.some((r) => r.method === 'POST' && r.url.includes('/drafts')));
  }
});

test('If the original cannot be read, no draft is created', async () => {
  // Fail closed. A rule that stops applying when a fetch fails is not a rule.
  const { antworten, rufe: netz } = await rufe(
    [werkzeug('draft_reply', { account: KONTO, id: 'abc123', body: 'T' })],
    { antworten: { 'messages/abc123': { status: 404, body: { error: 'gone' } } } });
  assert.ok(antwortZu(antworten, 2).result?.isError);
  assert.ok(!netz.some((r) => r.method === 'POST' && r.url.includes('/drafts')));
});

// ------------------------------------------------------- redirect uri -----

test('The redirect comes from the client file, not from a guess', async () => {
  // Google answers redirect_uri_mismatch unless this matches, to the
  // character, what is registered for the client. A Desktop client is
  // registered as bare `http://localhost`; a hard-coded port and path would be
  // wrong for every one of them, and the failure appears on the consent
  // screen where it is least convenient to debug.
  // Deliberately NOT the fallback value: a client file that happens to agree
  // with the default would make this case pass no matter where the value came
  // from, which is how a test ends up proving nothing.
  const REGISTRIERT = 'http://localhost:9876/oauth2callback';
  const wurzel = konfigWurzel('umleitung');
  fs.writeFileSync(path.join(wurzel, 'oauth-client.json'), JSON.stringify({
    installed: { client_id: 'x', client_secret: 'y',
      redirect_uris: [REGISTRIERT] } }), { mode: 0o600 });
  const { antworten } = await rufe(
    [werkzeug('begin_account_auth', { account: 'neu' })], { wurzel });
  const url = new URL(daten(antworten, 2).consent_url);
  assert.equal(url.searchParams.get('redirect_uri'), REGISTRIERT);
  assert.equal(url.origin + url.pathname,
    'https://accounts.google.com/o/oauth2/v2/auth');
  // Offline access with a forced consent, or Google returns no refresh token
  // on a repeat grant and the account dies silently an hour later.
  assert.equal(url.searchParams.get('access_type'), 'offline');
  assert.equal(url.searchParams.get('prompt'), 'consent');
  assert.equal(url.searchParams.get('scope'),
    'https://www.googleapis.com/auth/gmail.readonly '
    + 'https://www.googleapis.com/auth/gmail.compose');
});

// ---------------------------------------------------- header injection -----

test('A line break in a header is refused, not stripped', async () => {
  // A silently altered recipient is worse than a failed call: the caller
  // believes the draft went to the address they named.
  for (const args of [
    { account: KONTO, to: 'a@x.org\r\nBcc: thief@evil.example', subject: 'S', body: 'T' },
    { account: KONTO, to: 'a@x.org', subject: 'S\nX-Spoof: yes', body: 'T' },
    { account: KONTO, to: 'a@x.org', cc: 'b@x.org\nTo: thief@evil.example', subject: 'S', body: 'T' },
  ]) {
    const { antworten, rufe: netz } = await rufe([werkzeug('draft_create', args)],
      { antworten: { 'users/me/drafts': { body: { id: 'd1' } } } });
    assert.ok(antwortZu(antworten, 2).result?.isError,
      `not refused: ${JSON.stringify(args)}`);
    assert.ok(!netz.some((r) => r.method === 'POST' && r.url.includes('/drafts')));
  }
});

test('An ordinary draft is built and posted', async () => {
  const { antworten, rufe: netz } = await rufe(
    [werkzeug('draft_create', { account: KONTO, to: 'a@x.org', subject: 'S', body: 'Hallo' })],
    { antworten: { 'users/me/drafts': { body: { id: 'd1' } } } });
  assert.ok(!antwortZu(antworten, 2).result?.isError, inhalt(antworten, 2).slice(0, 200));
  const post = netz.find((r) => r.method === 'POST' && r.url.includes('/drafts'));
  const roh = Buffer.from(JSON.parse(post.body).message.raw, 'base64url').toString('utf8');
  assert.ok(roh.includes(`From: ${EIGENE}`), roh.slice(0, 200));
  assert.ok(roh.includes('To: a@x.org'));
  assert.ok(roh.includes('Hallo'));
});

// --------------------------------------------------------- the filter -----

test('One-time codes do not reach the model, ids do', async () => {
  const { antworten } = await rufe(
    [werkzeug('message_search', { account: KONTO, query: 'is:unread' })],
    { antworten: {
      'users/me/messages?': { body: { messages: [{ id: '19c4f1a2b3d4e5f6' }] } },
      'messages/19c4f1a2b3d4e5f6': { body: {
        id: '19c4f1a2b3d4e5f6', threadId: '19c4f1a2b3d4e5f6',
        snippet: '416107 is your code',
        payload: { headers: [{ name: 'Subject', value: '416107 is your code' }] } } },
    } });
  const text = inhalt(antworten, 2);
  assert.ok(!text.includes('416107'), 'the code must not get through');
  assert.ok(text.includes('[...]'));
  assert.ok(text.includes('19c4f1a2b3d4e5f6'), 'the id must survive');
});

// ------------------------------------------------------- attachments ------

test('An attachment cannot escape the quarantine directory', async () => {
  const inhaltB64 = Buffer.from('x').toString('base64url');
  for (const name of ['../../../etc/passwd', '/etc/passwd', '..', '.bashrc']) {
    const { antworten } = await rufe([werkzeug('attachment_download',
      { account: KONTO, messageId: 'm1', attachmentId: 'a1', filename: name })],
      { antworten: { '/attachments/a1': { body: { data: inhaltB64, size: 1 } } } });
    const a = antwortZu(antworten, 2);
    if (a.result?.isError) continue;
    const ziel = daten(antworten, 2).saved_to;
    assert.ok(ziel.startsWith(path.join(tmp, 'anhaenge') + path.sep),
      `${name} landed at ${ziel}`);
    assert.ok(!ziel.includes('..'), ziel);
  }
});

// ------------------------------------------------------- file modes -------

test('Secrets are written 0600 in a 0700 directory', async () => {
  const d = path.join(tmp, 'geheim', 'tief');
  const f = path.join(d, 'token.json');
  await schreibeGeheim(f, '{"refresh_token":"x"}\n');
  assert.equal(fs.statSync(f).mode & 0o777, 0o600);
  assert.equal(fs.statSync(d).mode & 0o777, 0o700);
  // And no leftover temporary file that might carry a looser mode.
  assert.deepEqual(fs.readdirSync(d), ['token.json']);
});

test('A token other users can read is refused, not used', async () => {
  // A refresh token does not expire. Whoever reads one has that mailbox until
  // the grant is revoked by hand, so a loose mode must stop the server rather
  // than be silently tolerated.
  const wurzel = konfigWurzel('offen');
  const tokendatei = path.join(wurzel, 'accounts', KONTO, 'token.json');
  fs.chmodSync(tokendatei, 0o644);
  await assert.rejects(() => pruefeRechte(tokendatei), /readable by group or others/);
  const { antworten } = await rufe([werkzeug('labels_list', { account: KONTO })], { wurzel });
  assert.ok(antwortZu(antworten, 2).result?.isError, inhalt(antworten, 2).slice(0, 200));
});

test('An unknown or malformed account id is refused before any request', async () => {
  for (const konto of ['gibtsnicht', '../../etc', 'UPPER', 'a'.repeat(80)]) {
    const { antworten, rufe: netz } = await rufe(
      [werkzeug('labels_list', { account: konto })]);
    const a = antwortZu(antworten, 2);
    assert.ok(a.result?.isError || a.error, `${konto} was accepted`);
    assert.equal(netz.length, 0, `${konto} caused a request: ${JSON.stringify(netz)}`);
  }
});

// ------------------------------------------------------ soft and hard -----

test('A connection failure ends a read softly, without an empty list', async () => {
  const { antworten } = await rufe(
    [werkzeug('message_search', { account: KONTO, query: '' })],
    { fehler: 'fetch failed: ECONNREFUSED' });
  const a = antwortZu(antworten, 2);
  assert.ok(!a.result?.isError, inhalt(antworten, 2).slice(0, 200));
  const d = daten(antworten, 2);
  assert.equal(d.soft, true);
  assert.ok(!('messages' in d), inhalt(antworten, 2));
});

test('An authorisation failure stays hard', async () => {
  // Someone has to act; this is not "try again later".
  const { antworten } = await rufe(
    [werkzeug('labels_list', { account: KONTO })],
    { antworten: { 'oauth2.googleapis.com/token': { status: 400,
      body: { error: 'invalid_grant' } } } });
  assert.ok(antwortZu(antworten, 2).result?.isError);
});
