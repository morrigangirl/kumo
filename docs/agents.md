# Codex and Claude browser control

Kumo includes a local MCP server with eight browser tools: list granted tabs, open a tab, navigate within a granted origin, read a page snapshot, click, fill a text field, scroll, and close a granted tab. The code is in `agent-bridge/` and uses Node.js built-ins; no npm install is required. Node.js 22 or later and macOS or another Unix system are required.

The agent runs in **Codex Desktop or Claude Desktop**, using the account already signed into that client. Kumo supplies a local MCP browser toolset. Account access and organization policies remain with the chosen client; the bridge does not call provider APIs or import account tokens.

## Desktop setup

Install Node.js 22 or later, then open the packaged Kumo app once so macOS registers it. In Kumo's agent settings, copy the setup command for your desktop client. The commands work independently of the source checkout and the application's installation folder:

```sh
open -n -b app.kumo.browser --args --kumo-connect-codex-desktop
open -n -b app.kumo.browser --args --kumo-connect-claude-desktop
```

Run the command for each client you want to connect. Fully quit Claude Desktop before its setup command, then open it again afterward so it loads the new configuration. Setup installs a private copy of the bridge in `~/.kumo/agents/server/`. Its launcher resolves Node at runtime rather than recording the developer's Node or checkout path. The clients start this installed bridge over standard input/output, using this portable command:

```sh
/bin/sh -c 'exec "$HOME/.kumo/agents/server/run" mcp'
```

- **Codex Desktop:** setup finds the official Codex CLI, including the copy inside the desktop app, and uses `codex mcp add` to register `kumo`. The desktop app, CLI and IDE share the host's MCP configuration. Existing unrelated servers remain configured. [Official OpenAI MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
- **Claude Desktop:** setup registers `mcpServers.kumo` in `~/Library/Application Support/Claude/claude_desktop_config.json`, preserving other configuration entries and making a private backup before changes. This configures Claude Desktop directly. Organization policy may disable local MCP servers. [Claude Desktop local MCP documentation](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop).

Kumo keeps the sealed extension source inside the app and loads a verified, versioned copy from its private profile. Chromium writes generated rule indexes into that runtime copy, preserving the app's signature. Each new source version gets its own directory so an active browser's extension code is not overwritten.

Reload Codex's MCP connections or start a new chat after installation; some versions require an application restart. Open Claude Desktop after completing its quit-and-setup sequence. Setup does not quit an active client or start an agent task. Check that the client lists the `kumo` server and its `browser_*` tools. If Claude's entry disappears after a configuration change, fully quit Claude, rerun its Kumo setup and reopen it.

In Kumo's agent settings, select the tabs you want to share, then choose **Allow selected tabs** and approve the website permissions. Enable new tabs only if you want the agent to create them. Ask your desktop client to use `browser_tabs` first. Access starts disabled and expires when the browser session ends or the bridge disconnects.

This supplies Kumo's MCP toolset to local desktop clients. It does not register Kumo as Chrome in a client's separate built-in computer-use browser integration. Remote/cloud clients require a separately supported transport; Kumo does not expose a public listener.

### Development profiles

From a source checkout, install the host for a disposable profile with:

```sh
./agent-bridge/run install \
  --extension-id YOUR_32_LETTER_EXTENSION_ID \
  --browser-profile "$HOME/Library/Application Support/Kumo"
```

Plain `install` writes the Native Messaging registration and manual MCP snippets. Add `--provider codex-desktop`, `--provider claude-desktop`, or `--provider all` to configure desktop clients. Desktop configuration uses the standard runtime in `~/.kumo/agents/`. For isolated development profiles, plain installation supports `KUMO_AGENT_DIR` set to a short absolute private directory and `--manifest-path` as an alternative to `--browser-profile`. Each runtime supports one connected browser profile.

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

The bridge tests exercise actual Unix sockets, token rejection, file modes, disabled state, tab/origin grants, discovery filtering, revocation during a request, timeouts, reconnect reset, native frame parsing, MCP schemas, and a Native Messaging host plus MCP subprocess exchange. The extension-agent tests exercise the real service-worker and newtab handlers, synchronous MV3 listener registration, displayed-origin binding, permission and navigation races, atomic multi-tab grants, malformed grant rejection, revocation races, tokenized sensitive fields, snapshot filtering, and Store origin/ID/CRX3 request handling. Store-helper tests also cover page UI and document confirmation. Portable Desktop setup tests cover copied runtime operation, client configuration, relocation, preservation of unrelated settings, and unsafe file rejection.

Real-browser integration QA also passed against the packaged Chromium runtime:

```sh
node scripts/smoke-agents.mjs
```

That check uses disposable profiles, mock Keychain, runtime directories, local HTTP fixtures, and an extension copy with test-only loopback website access. It verifies the actual Kumo grant/revoke buttons, Chromium's Native Messaging host, the authenticated local broker, visible snapshots without hidden/form values, real clicks and text entry, password/OTP/payment-field rejection across token/case/whitespace variants, and grant removal after a cross-origin redirect. It also rejects a stale dialog selection despite retained destination website permission and verifies that a refreshed explicit grant succeeds. Production extension permissions remain unchanged. No user accounts, saved credentials, provider logins, or provider tasks are accessed by these checks.
