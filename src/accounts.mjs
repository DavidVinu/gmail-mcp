// Account store: several Gmail accounts in one instance.
//
// Each account is a directory under the config root holding one token file.
// The OAuth client (client_id / client_secret) is shared by all of them and
// lives once at the root: it identifies the *application*, not the user, and
// duplicating it per account only multiplies the number of places a secret
// sits on disk.
//
// WHY THE FILE MODES ARE PART OF THIS FILE. A refresh token does not expire.
// Whoever reads one has that mailbox until the grant is revoked by hand. The
// reference implementation this replaces wrote both the token and the client
// secret with a plain writeFile and had no chmod anywhere in its source tree,
// so both landed at the process umask -- world-readable on a default Ubuntu.
// Here every write goes through `schreibeGeheim`, and a contract test asserts
// the resulting modes.

import { constants } from 'node:fs';
import { chmod, mkdir, readFile, readdir, rename, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const KONTO_MUSTER = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function konfigWurzel(env = process.env) {
  return env.GMAIL_MCP_CONFIG_DIR
    || path.join(env.HOME ?? '', '.config', 'gmail-mcp');
}

export const pfade = (wurzel, id) => ({
  wurzel,
  klient: path.join(wurzel, 'oauth-client.json'),
  kontenVerzeichnis: path.join(wurzel, 'accounts'),
  kontoVerzeichnis: path.join(wurzel, 'accounts', id ?? ''),
  token: path.join(wurzel, 'accounts', id ?? '', 'token.json'),
  meta: path.join(wurzel, 'accounts', id ?? '', 'meta.json'),
});

/** Write a secret so that only this user can read it, atomically.
 *
 * Atomically because a half-written token file is indistinguishable from a
 * revoked one, and the repair is a full re-authorisation. The temporary file
 * is created with the final mode, so the secret is never briefly world
 * readable between write and chmod.
 */
export async function schreibeGeheim(datei, inhalt) {
  await mkdir(path.dirname(datei), { recursive: true, mode: 0o700 });
  await chmod(path.dirname(datei), 0o700).catch(() => {});
  const tmp = `${datei}.${process.pid}.tmp`;
  await writeFile(tmp, inhalt, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await chmod(tmp, 0o600);
  await rename(tmp, datei);
}

/** Refuse to use a secret that other accounts on this machine can read. */
export async function pruefeRechte(datei) {
  const st = await stat(datei);
  if ((st.mode & 0o077) !== 0) {
    throw new Error(
      `${datei} is readable by group or others (${(st.mode & 0o777).toString(8)}). `
      + 'Expected 0600. A refresh token does not expire; fix the mode and '
      + 're-authorise, because it must be assumed to have leaked.');
  }
}

export async function ladeKlient(wurzel) {
  const p = pfade(wurzel).klient;
  await pruefeRechte(p);
  const roh = JSON.parse(await readFile(p, 'utf8'));
  // Google hands out the file under either key depending on the client type.
  const q = roh.installed ?? roh.web ?? roh;
  if (!q.client_id || !q.client_secret) {
    throw new Error(`${p}: client_id and client_secret required.`);
  }
  return { id: q.client_id, secret: q.client_secret };
}

export async function listeKonten(wurzel) {
  let namen = [];
  try {
    namen = await readdir(pfade(wurzel).kontenVerzeichnis);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    return [];
  }
  const aus = [];
  for (const id of namen.sort()) {
    if (!KONTO_MUSTER.test(id)) continue;
    const p = pfade(wurzel, id);
    let meta = {};
    try { meta = JSON.parse(await readFile(p.meta, 'utf8')); } catch { /* neu */ }
    let bereit = false;
    try {
      await stat(p.token);
      await pruefeRechte(p.token);
      bereit = true;
    } catch { /* nicht autorisiert oder unsichere Rechte */ }
    aus.push({ account: id, email: meta.email ?? null, authorised: bereit,
      scopes: meta.scopes ?? null, authorised_at: meta.authorised_at ?? null });
  }
  return aus;
}

export async function ladeToken(wurzel, id) {
  if (!KONTO_MUSTER.test(id)) throw new Error(`invalid account id: ${id}`);
  const p = pfade(wurzel, id);
  try {
    await pruefeRechte(p.token);
  } catch (e) {
    if (e.code === 'ENOENT') {
      throw new Error(
        `account "${id}" is not authorised yet. Run begin_account_auth `
        + 'and finish_account_auth for it, or list_accounts to see what exists.');
    }
    throw e;
  }
  return JSON.parse(await readFile(p.token, 'utf8'));
}

export async function speichereToken(wurzel, id, token, meta) {
  const p = pfade(wurzel, id);
  await schreibeGeheim(p.token, `${JSON.stringify(token, null, 2)}\n`);
  if (meta) {
    await schreibeGeheim(p.meta, `${JSON.stringify(meta, null, 2)}\n`);
  }
}

export { constants };
