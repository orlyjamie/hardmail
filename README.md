# hardmail

Hardened, **shell-free** email tools for the [Hermes](https://github.com/NousResearch/Hermes) agent. Gmail (OAuth) by default, with an IMAP/SMTP or Resend backend for non-Google providers.

## Why this exists

Indirect prompt injection fires when an agent **reads** content, not when it acts. An agent whose job is to read your inbox is, by definition, reading untrusted text written by strangers. The standard way to give an agent email is to let it drive a CLI client (e.g. `himalaya`) through the general-purpose `terminal` tool — which means the mail-reading surface is **holding a shell**. A prompt injection in an email can then run arbitrary commands, not just email ones.

hardmail removes that coupling. It talks to the mail provider through a **native API with structured arguments**, so the agent can do the entire email job with **no `terminal` in its toolset**. The exfiltration channel is gone because the capability was never granted.

> The fix for "the mail reader has a shell" is not a better filter. It is to not give the mail reader a shell. hardmail is what makes that practical.

## Tools

| Tool | Side effects | Gated? |
|---|---|---|
| `mail_search` | none (read) | no |
| `mail_get` | none (read) | no |
| `mail_get_attachment` | none (read) | no |
| `mail_send` | **outbound** | **yes — self-gated, fail-closed** |

Reads are open and side-effect-free. `mail_send` is the only egress: it **stops for operator approval** and shows a card with **recipient, subject, attachments, and a body preview** before anything leaves. No approval (or an unreachable approval channel) means **nothing is sent**. Message bodies and attachments are treated as untrusted data, never as instructions.

## Install

```bash
mkdir -p "$HERMES_HOME/plugins"
cp -r hardmail "$HERMES_HOME/plugins/hardmail"        # $HERMES_HOME defaults to ~/.hermes
pip install -r "$HERMES_HOME/plugins/hardmail/requirements.txt"   # Gmail backend only
```

Enable it and **scope it to the surface that needs it** in `$HERMES_HOME/config.yaml`:

```yaml
plugins:
  enabled:
    - hardmail

# Cap the untrusted-input surface to email (+ calendar) ONLY — no terminal/web/browser.
# This is the real defence; the plugin is what makes it survivable.
platform_toolsets:
  telegram: [hardmail, hardcal]
```

## Setup — Gmail (default backend)

OAuth is driven entirely from chat (operator-only slash command; the model cannot invoke it, so an injected email can never trigger or hijack auth):

1. Create a **Desktop OAuth client** in Google Cloud (restricted Gmail scopes), download the client secret JSON.
2. `/hardmail setup` — prints what to do next.
3. `/hardmail client <paste client_secret JSON>` — stores the client.
4. `/hardmail url` — open the printed consent URL in your browser, approve.
5. `/hardmail code <CODE>` — exchanges the code, writes `$HERMES_HOME/google_token.json` (Gmail **and** Calendar scopes, shared with [hardcal](../hardcal)).
6. `/hardmail status` — verify connection.

The token is restricted-scope (`gmail.readonly`, `gmail.send`, `gmail.modify`, `calendar`) and lives only in `$HERMES_HOME`. It is **never** committed (see `.gitignore`).

## Setup — IMAP / SMTP / Resend (non-Google)

Set `HARDMAIL_BACKEND=imap` and the relevant environment variables:

```bash
# Read (IMAP)
HARDMAIL_IMAP_HOST=imap.example.com
HARDMAIL_IMAP_PORT=993
HARDMAIL_IMAP_USER=you@example.com
HARDMAIL_IMAP_PASS=...                  # use an app password

# Send — SMTP (default) ...
HARDMAIL_SMTP_HOST=smtp.example.com
HARDMAIL_SMTP_PORT=587
HARDMAIL_SMTP_USER=you@example.com
HARDMAIL_SMTP_PASS=...
HARDMAIL_FROM=you@example.com

# ... or send via Resend instead
HARDMAIL_SEND_BACKEND=resend
RESEND_API_KEY=...
HARDMAIL_FROM=you@example.com
```

Put secrets in your platform's secret store (e.g. `flyctl secrets set`), never in the repo.

## Requirements

- Hermes with the plugin system.
- Gmail backend: `google-auth`, `google-auth-oauthlib`, `google-api-python-client` (see `requirements.txt`).
- IMAP/SMTP/Resend backend: standard library only.

## Pairs well with

- **[hardcal](../hardcal)** — shell-free Google Calendar; reuses the same OAuth token.
- **[youshallnotpass](../youshallnotpass)** — per-tool/per-platform approval gate for the capabilities you *do* keep.

## License

MIT © 2026 Jamieson O'Reilly (theonejvo)
