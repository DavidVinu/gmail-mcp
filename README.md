# gmail-mcp

An MCP server that gives an AI assistant several Gmail accounts at once — read
and draft only. It **cannot send**, it **cannot delete**, and it **cannot reach
anything but the Gmail API**.

Every tool takes a required `account` parameter; `list_accounts` shows what is
configured. Adding another account is an OAuth flow at runtime, not a redeploy.

## What it cannot do, and where the guarantee actually lives

| | How it is prevented |
| - | - |
| Send | No send tool. No code path reaches `messages/send` or `drafts/*/send`, and `gmailUrl` refuses those paths outright. |
| Delete | Not offered at all. Gmail's `drafts.delete` is permanent, so there is no delete tool of any kind. |
| Change filters or forwarding | `gmail.settings.basic` is not requested, and `settings/` is a refused path. |
| Touch Drive, Docs, Sheets, Calendar | Those scopes are not requested. |
| Contact anything but Google | Three constant hosts, one outbound function, `redirect: 'error'`. A contract test scans the source for URL literals. |

**One thing you must know, because it is a real limit and not a detail.**
Google has **no draft-only scope**. `gmail.compose` is the narrowest scope that
can create a draft, and at the API level it also permits sending. So the grant
this server holds *could* send; the reason it cannot is that this server offers
no send tool and no code path that reaches the send endpoint. That is the same
shape of guarantee the Proton server gives, and it is worth stating plainly
rather than implying that Google enforces it.

The second consequence of staying narrow: **this server cannot mark anything as
read.** Changing labels needs `gmail.modify`, which also grants send. That was
the wrong trade, so reading leaves the mailbox untouched.

## Requirements

- Node.js 20 or newer
- Your own Google OAuth client (below)

## What you have to do in the Google Cloud Console

This part cannot be automated — it is your account and your consent screen.

1. **Create or pick a project.** console.cloud.google.com → project selector →
   *New project*. Any name.
2. **Enable the Gmail API.** *APIs & Services → Library* → search "Gmail API" →
   *Enable*. Enable nothing else; this server uses nothing else.
3. **Configure the consent screen.** *APIs & Services → OAuth consent screen*.
   - User type: **External** (unless every mailbox is in a Workspace you own,
     then Internal).
   - Fill in app name and your own address; nothing else is required.
   - **Scopes:** add exactly these two, and no others:
     ```
     https://www.googleapis.com/auth/gmail.readonly
     https://www.googleapis.com/auth/gmail.compose
     ```
   - **Test users:** add every Gmail address you intend to connect. While the
     app is in *Testing*, only listed addresses can authorise it, and refresh
     tokens expire after 7 days. For a permanent setup either publish the app
     (Google will ask for verification because Gmail scopes are sensitive) or
     keep it in Testing and re-authorise weekly. **Decide this before you rely
     on it** — a token that quietly dies after a week is the kind of failure
     that goes unnoticed.
4. **Create the client.** *APIs & Services → Credentials → Create credentials →
   OAuth client ID → Desktop app*. Download the JSON.
5. **Install it:**
   ```sh
   mkdir -p ~/.config/gmail-mcp
   install -m 0600 ~/Downloads/client_secret_*.json ~/.config/gmail-mcp/oauth-client.json
   chmod 700 ~/.config/gmail-mcp
   ```
   The server refuses to start from a file that group or others can read.

If you use a **Web application** client instead of Desktop, add your redirect
URI there and set `GMAIL_MCP_REDIRECT_URI` to the same value.

## Adding an account

Ask the assistant, or call the tools directly:

1. `begin_account_auth` with `account: "privat"` — a short id you choose.
   It returns a Google consent URL.
2. Open the URL **as the owner of that mailbox** and approve.
3. **Your browser will then show an error** — "This site can't be reached",
   "connection refused", or a blank page. **That is expected and is not a
   failure.** Nothing listens on the redirect address; the part that matters is
   in the address bar:

   ```
   http://localhost/?state=privat&code=4/0AX4X...&scope=...
                                  ^^^^^^^^^^^^^^ this
   ```

   Copy the value of `code=`, up to the next `&`.
4. `finish_account_auth` with the same `account` and that `code`. The code is
   single-use and expires within minutes, so do this straight away; if it
   fails, start again at step 1.

The redirect address is taken from your client file, because it has to match
what Google registered for that client to the character — a mismatch shows up
as `redirect_uri_mismatch` on the consent screen. `GMAIL_MCP_REDIRECT_URI` only
applies if the file names none.

The refresh token is written to `~/.config/gmail-mcp/accounts/<id>/token.json`
with mode `0600` in a `0700` directory, atomically. The account's address is
read back from Gmail and stored in `meta.json`; `list_accounts` shows it.

Repeat for each mailbox. Ids must match `[a-z0-9][a-z0-9._-]{0,63}`.

To revoke: delete the account directory, and remove the app at
myaccount.google.com/permissions for that address. Deleting the file alone
leaves the grant standing on Google's side.

## The recipient rule

A reply draft is only created if the message was addressed to that account
(`To` or `Cc`). If it went somewhere else, the call is refused and both
addresses are named. It fails closed: if the original cannot be read, no draft
is created.

Only `To` and `Cc` are examined. `Delivered-To` and `X-Original-To` carry the
delivering mailbox rather than the address the mail was sent to, and checking
those would let through exactly the cases this rule is about.

## Running it

### Locally (stdio)

```sh
claude mcp add gmail --scope user -- /path/to/gmail-mcp/src/stdio.mjs
```

Claude Code reads `~/.claude.json`, **not** `claude_desktop_config.json`.

### Over HTTP

```sh
mkdir -p ~/.config/gmail-mcp
install -m 0600 /dev/null ~/.config/gmail-mcp/http-token
openssl rand -hex 32 > ~/.config/gmail-mcp/http-token
```

Then run `src/http.mjs`, or install `systemd/gmail-mcp.service`. It binds to
`127.0.0.1` only; exposing it is your job and your risk — put it behind a
tunnel or an authenticated proxy you control.

The endpoint takes a static bearer token and has **no OAuth**: it answers `404`
on `/.well-known/*` and sends no `WWW-Authenticate`, because a client that sees
either will try dynamic client registration and fail confusingly. An unknown
session id answers `404` rather than `400`, so a client re-initializes instead
of retrying a session that a restart threw away.

## Configuration

| Variable | Default |
| - | - |
| `GMAIL_MCP_CONFIG_DIR` | `~/.config/gmail-mcp` |
| `GMAIL_MCP_ATTACHMENT_DIR` | `~/.local/share/gmail-mcp/attachments` |
| `GMAIL_MCP_REDIRECT_URI` | the client file's own value, else `http://localhost` |
| `GMAIL_MCP_TOKEN_FILE` | `~/.config/gmail-mcp/http-token` (HTTP only) |
| `GMAIL_MCP_PORT` | `18791` (HTTP only) |
| `GMAIL_MCP_ADDRESS` | `127.0.0.1` (HTTP only) |

## Tools

`list_accounts`, `begin_account_auth`, `finish_account_auth`, `labels_list`,
`message_search`, `message_read`, `thread_read`, `draft_list`, `draft_read`,
`draft_create`, `draft_reply`, `attachment_download`.

## One-time codes

Reading mail means confirmation codes reach the model. `src/otp-filter.mjs`
masks them first — copied verbatim from the protonmail-mcp repo, where it also
carries a differential test against the Python original it was ported from.
Gmail's opaque ids are exempt by field name *and* shape, because destroying
them makes every follow-up call impossible.

Layer 2 blanks the whole string when text merely *announces* a code, so a reply
preview quoting such a message can come back empty. The draft is still created
correctly.

## Tests

```sh
npm test
```

41 cases, no network and no Google account required: global `fetch` is replaced
via `node --import`, so the production build has no switch for redirecting its
own outbound door. Four mutations are checked by hand and each is caught by
exactly one case — recipient rule off, send path allowed, header check removed,
tokens written world-readable.

## Why this is not tszaks/gmail-multi-inbox-mcp

That project was the starting point and was reviewed first. It requests
`https://mail.google.com/` (full Gmail including permanent delete),
`gmail.settings.basic` (which can create forwarding addresses), full Drive,
Sheets, Docs and Calendar; it ships `send_email`, `send_draft`, `trash_emails`,
`share_drive_file` and 55 more tools; its HTTP mode binds `0.0.0.0` with no
authentication at all; it writes tokens and the client secret with a plain
`writeFile` and contains no `chmod` anywhere; and `unsubscribe_from_email`
POSTs to a URL taken from the `List-Unsubscribe` header — an address chosen by
whoever sent the mail, `http://` included, with no allowlist and no guard
against private ranges.

None of that is a criticism of its goals; it is simply a different tool. This
one is written to a narrower brief.

## License

MIT
