# Codex and Claude browser control

Kumo includes a local MCP server with eight browser tools: list granted tabs, open a tab, navigate within a granted origin, read a page snapshot, click, fill a text field, scroll, and close a granted tab. The code is in `agent-bridge/` and uses Node.js built-ins; no npm install is required. Node.js 22 or later and macOS or another Unix system are required.

The agent runs in the official Codex or Claude Code client and keeps its own account authentication. Codex supports ChatGPT subscription sign-in and API-key sign-in; workspace permissions still apply. [Official OpenAI authentication documentation](https://learn.chatgpt.com/docs/auth).

Claude Code supports eligible personal subscriptions and Team/Enterprise accounts through its own login flow. Use the account and billing method you normally use with Claude Code. [Official Claude Code authentication documentation](https://code.claude.com/docs/en/authentication).

Kumo does not import provider tokens, read CLI credential stores, turn a consumer subscription into an API key, or offer a separate provider login implementation. The browser bridge itself does not call either provider API. Account eligibility, organization policies, and billing remain with the chosen official client.

## Setup

1. Open `chrome://extensions` in Kumo, enable developer mode, and find the Kumo extension ID.
2. Install its Native Messaging host, using the same user-data directory that Kumo was launched with:

   ```sh
   node agent-bridge/cli.mjs install \
     --extension-id YOUR_32_LETTER_EXTENSION_ID \
     --browser-profile "$HOME/Library/Application Support/Kumo"
   ```

   The installer also accepts `--manifest-path /absolute/path/com.kumo.agent_bridge.json` instead of `--browser-profile` when your browser uses a different host lookup directory. Installation writes a host manifest, a private launcher, and Kumo-specific MCP configuration snippets. It does not modify existing Codex or Claude configurations or run an agent task.

3. Inspect the generated configuration paths printed by the installer. By default they are:

   - `~/.kumo/agents/codex-config.toml`: merge this MCP table into your chosen Codex configuration, or add the displayed command through its MCP settings.
   - `~/.kumo/agents/claude-mcp.json`: supply this with `claude --mcp-config "$HOME/.kumo/agents/claude-mcp.json"`, or add the server to your chosen Claude Code configuration.

   Both clients support local stdio MCP servers. The Codex desktop app, CLI, and IDE extension can share host configuration; remote web/cloud clients need their own supported connection path. [Official OpenAI MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

4. In Kumo settings, enable agent control and grant the specific tabs you want to share. Grant website access when requested. Allow new tabs only if you want the agent to create tabs. Control starts disabled, and grants expire when the browser session ends or the bridge disconnects.
5. In your chosen agent, ask it to use `browser_tabs` first. That returns only granted tabs. A safe first task is to summarize the visible content of a page you selected.

For a separate development profile, set `KUMO_AGENT_DIR` to a short absolute directory before running the installer and use the generated snippets for that profile. A runtime supports one connected Kumo browser profile at a time. A different runtime directory isolates another profile and its local token.

## Access boundaries

The browser extension owns permission state. Grant confirmation binds each selected tab to the exact origin displayed in the dialog, captured before the website-permission prompt. The worker checks the current tab and website permission again before publishing the grant. A changed origin or pending navigation rejects the selection and refreshes the choices; enabling access then requires another explicit confirmation. Retained website permission does not grant agent control by itself. The local broker independently requires an enabled session and a grant matching the requested tab and origin. Cross-origin navigation loses the grant; the user must grant the destination again. New tabs require a separate opt-in. Private/incognito tabs are excluded by the extension.

Local phishing warnings may already have website access when enabled. That permission supports the on-device detector and does not create agent grants; each agent tab still requires its separate displayed-origin confirmation. The phishing helper receives no agent commands or provider authentication.

The transport is a private Unix socket, not a network listener or public remote-debugging endpoint. It authenticates local peers with a randomly generated token in a user-owned mode-0600 file; the runtime directory is mode 0700. Chrome Native Messaging also restricts the caller to registered extension origins. The token never goes into page scripts, MCP configuration, stdout, or the extension. Other processes running as the same OS user remain part of the local trust boundary and could read the token. This is not process attestation.

All agents connected to the same runtime share the currently granted tab set. Kumo does not cryptographically identify whether a caller is Codex or Claude. Disable control or use separate profiles/runtime directories when you need separate access.

The bridge exposes no arbitrary JavaScript, cookie, credential-store, filesystem, download, or browser-settings tools. Page actions are confined to the main document. Password and selected sensitive form controls are excluded from clicks, typing and snapshot control metadata; snapshots omit form values. Verification-code detection matches autocomplete tokens regardless of case, including section prefixes and ASCII whitespace. Payment and password autocomplete exclusions are also case insensitive. This depends on the page's markup and is not a guarantee that every sensitive field is recognized. Visible page content can still contain personal information. Grant only tabs whose content you intend the selected agent to receive.

Revocation prevents pending page results from reaching the agent; a command already executed on the page cannot be undone. Browser tools can still click a consequential action on a granted page. MCP tool annotations and server instructions ask the agent to obtain authorization for purchases, messages, and account changes, while the agent client's own approval policy remains responsible for that confirmation. Page text is untrusted input and must never override user instructions.

Snapshots currently provide DOM text, links, and basic controls rather than screenshots or a full accessibility tree. Cross-origin frames, closed shadow roots, native dialogs, browser chrome, passkey dialogs, and Apple Passwords are outside this bridge.

## Protocol and checks

The stdio endpoint implements JSON-RPC MCP initialization, ping, tool discovery, and tool calls using the stable `2025-06-18` protocol revision. Native Messaging uses Chrome's length-prefixed frames; the broker uses bounded newline-delimited JSON. Replies expire after 20 seconds and are never retried automatically, so a click or submission is not duplicated after a timeout.

Extension → host state:

```json
{"type":"state","enabled":true,"allowNewTabs":false,"grants":[{"tabId":12,"origin":"https://example.com"}]}
```

Host → extension command:

```json
{"type":"command","id":"request-uuid","action":"tab.snapshot","params":{"tabId":12}}
```

Extension → host reply:

```json
{"type":"result","id":"request-uuid","result":{"title":"Example","text":"Visible page text"}}
```

Errors use `{"type":"result","id":"request-uuid","error":{"message":"Reason"}}`. The host sends `{"type":"ready"}` once connected and `{"type":"stateApplied","enabled":true,"grantCount":1}` after accepting a state update. These are status messages, never commands. Permissions and results live in memory; the broker does not save page contents or action logs.

Run:

```sh
node --test agent-bridge/test/*.test.mjs
```

The 10 bridge tests exercise actual Unix sockets, token rejection, file modes, disabled state, tab/origin grants, discovery filtering, revocation during a request, timeouts, reconnect reset, native frame parsing, MCP schemas, and a Native Messaging host plus MCP subprocess exchange. The 35 extension-agent tests exercise the real service-worker and newtab handlers, synchronous MV3 listener registration, displayed-origin binding, permission and navigation races, atomic multi-tab grants, malformed grant rejection, revocation races, tokenized sensitive fields, snapshot filtering, and Store origin/ID/CRX3 request handling. Eight additional Store-helper tests cover its page UI and document confirmation. The full JavaScript suite now has 102 passing tests, including 36 phishing regressions; the [port validation](security-audits/2026-10-19/phishlang-port.md) also records a fresh packaged-browser agent check.

Real-browser integration QA also passed against the packaged Chromium runtime:

```sh
node scripts/smoke-agents.mjs
```

That check uses disposable profiles, mock Keychain, runtime directories, local HTTP fixtures, and an extension copy with test-only loopback website access. It verifies the actual Kumo grant/revoke buttons, Chromium's Native Messaging host, the authenticated local broker, visible snapshots without hidden/form values, real clicks and text entry, password/OTP/payment-field rejection across token/case/whitespace variants, and grant removal after a cross-origin redirect. It also rejects a stale dialog selection despite retained destination website permission and verifies that a refreshed explicit grant succeeds. Production extension permissions remain unchanged. No user accounts, saved credentials, provider logins, or provider tasks are accessed by these checks.
