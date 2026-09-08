// Harness: the real server over stdio, with global fetch replaced and its own
// config root. Nothing here touches a real Google account or the real home.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const hier = path.dirname(fileURLToPath(import.meta.url));
export const REPO = path.dirname(hier);
export const STDIO = path.join(REPO, 'src/stdio.mjs');
export const HTTP = path.join(REPO, 'src/http.mjs');
export const MOCK = path.join(hier, 'fetch-mock.mjs');

export const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-mcp-test-'));
process.on('exit', () => fs.rmSync(tmp, { recursive: true, force: true }));

export const KONTO = 'probe';
export const EIGENE = 'me@example.org';

/** A config root with one authorised account, modes as production writes them. */
export function konfigWurzel(name = 'konf') {
  const wurzel = path.join(tmp, name);
  const kdir = path.join(wurzel, 'accounts', KONTO);
  fs.mkdirSync(kdir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(wurzel, 'oauth-client.json'), JSON.stringify({
    installed: { client_id: 'probe-id.apps.googleusercontent.com',
      client_secret: 'probe-secret' } }), { mode: 0o600 });
  fs.writeFileSync(path.join(kdir, 'token.json'),
    JSON.stringify({ refresh_token: 'probe-refresh' }), { mode: 0o600 });
  fs.writeFileSync(path.join(kdir, 'meta.json'),
    JSON.stringify({ email: EIGENE }), { mode: 0o600 });
  return wurzel;
}

export const ANTWORTEN_BASIS = {
  'oauth2.googleapis.com/token': { body: { access_token: 'probe-zugang', expires_in: 3600 } },
  'users/me/profile': { body: { emailAddress: EIGENE } },
};

export function rufe(anfragen, { wurzel, antworten = {}, fehler, env = {},
  eintrag = STDIO } = {}) {
  const protokoll = path.join(tmp, `fetch-${Math.random()}.jsonl`);
  const kind = spawn(process.execPath, ['--import', MOCK, eintrag], {
    env: {
      ...process.env,
      HOME: tmp,
      GMAIL_MCP_CONFIG_DIR: wurzel ?? konfigWurzel(`k-${Math.random()}`),
      GMAIL_MCP_ATTACHMENT_DIR: path.join(tmp, 'anhaenge'),
      FETCH_MOCK_LOG: protokoll,
      FETCH_MOCK_RESPONSES: JSON.stringify({ ...ANTWORTEN_BASIS, ...antworten }),
      ...(fehler ? { FETCH_MOCK_FAIL: fehler } : {}),
      ...env,
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const zeilen = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {},
      clientInfo: { name: 'contract', version: '0' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    ...anfragen,
  ];
  kind.stdin.write(zeilen.map((z) => JSON.stringify(z)).join('\n') + '\n');
  kind.stdin.end();
  return new Promise((fertig) => {
    let aus = '';
    let err = '';
    kind.stdout.on('data', (d) => { aus += d; });
    kind.stderr.on('data', (d) => { err += d; });
    kind.on('close', () => {
      const antworten_ = aus.split('\n').filter(Boolean).map((z) => {
        try { return JSON.parse(z); } catch { return null; }
      }).filter(Boolean);
      const rufe_ = fs.existsSync(protokoll)
        ? fs.readFileSync(protokoll, 'utf8').split('\n').filter(Boolean).map((z) => JSON.parse(z))
        : [];
      fertig({ antworten: antworten_, rufe: rufe_, stderr: err });
    });
  });
}

export const werkzeug = (name, args, id = 2) => ({
  jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args },
});
export const antwortZu = (a, id) => a.find((x) => x.id === id);
export const inhalt = (a, id) => antwortZu(a, id)?.result?.content?.[0]?.text ?? '';
export const daten = (a, id) => JSON.parse(inhalt(a, id));
