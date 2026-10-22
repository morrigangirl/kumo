# Codex and Claude browser control

The native Kumo implementation provides eight local MCP browser tools: list granted tabs, open a tab, navigate within a granted origin, read a page snapshot, click, fill ordinary text fields, scroll and request that a granted tab close. The browser implementation is in `native/browser/agents/`; the MCP transport and desktop configuration code are in `agent-bridge/`.

This describes the current native development implementation. The published 0.1.2 release uses the historical extension bridge. Full native browser/runtime qualification is still pending.

## Desktop setup

Open **Settings → Kumo → Codex and Claude**, then choose **Connect Codex Desktop** or **Connect Claude Desktop**. No command copying or separate Node installation is required. Kumo bundles a pinned Apple Silicon Node runtime and runs it with JIT and WebAssembly disabled.

Setup preserves unrelated client configuration. Codex registration uses the official installed Codex CLI; Claude registration merges its desktop JSON configuration with a private backup. A missing client, malformed configuration, unsafe file or organization restriction is reported without overwriting unrelated settings. Reload MCP connections or restart the client when Kumo reports that configuration is complete. Kumo does not restart clients or start agent tasks.

The desktop client keeps its own consumer or business account sign-in. Kumo does not extract account tokens or call provider inference APIs. [OpenAI's MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) and [Claude's local MCP documentation](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) describe the client requirements. Organization policy can restrict local MCP servers.

Configuration and an active connection are different states. A configured server can appear in a desktop client while the browser is closed, but browser tool calls then fail. Kumo starts the browser authority channel itself; MCP discovery cannot start it.

## Access boundaries

Select tabs in Settings, review their displayed origins, then choose **Allow selected tabs**. Agent access starts off and is held only in memory. New tabs require a separate opt-in. Private/incognito/guest tabs and internal browser pages are excluded. Changing a tab's origin removes its grant. A stale selection cannot authorize a different origin after a navigation. Navigation invalidates pending document results; same-origin navigation does not permanently remove the origin grant.

The browser independently rechecks profile, tab, origin, document identity and permission generation for every action and result. The broker also validates enabled state and exact tab/origin grants. Revoke all access in Settings to invalidate pending results. Commands already executed cannot be undone, and a normal close request may show a page's unsaved-changes prompt.

The browser launches its fixed bundled broker through private inherited pipes. Only that channel can publish browser grants and results. MCP clients connect through a private, profile-specific Unix socket with an owner-only token. The socket accepts agent requests, never a browser or extension role. No public TCP listener or remote-debugging endpoint is enabled. Other processes running as the same OS user remain within the local trust boundary; this is not caller process attestation.

A versioned private MCP runtime makes desktop configuration independent of the source checkout and installed app folder. Kumo copies only its fixed bundled executable, JavaScript and notices, clears Node injection environment variables and preserves unrelated configuration. Profile identifiers are opaque; page content and credentials are not placed in client configuration.

Both clients share the profile's granted tab set. The local broker does not cryptographically identify a caller as Codex or Claude. Use separate profiles when separate access is required.

The toolset exposes no arbitrary JavaScript, cookies, credential stores, filesystem access or browser settings actions. Page operations are confined to the main document. Snapshots omit form values and exclude password, verification-code and payment controls. This depends on page markup; visible page content can still contain personal information. Only grant pages whose visible content you intend an agent to receive.

Client approval policies remain responsible for authorization of consequential actions such as purchases, messages and account changes. Page text is untrusted and cannot replace the user's instructions. Cross-origin frames, closed shadow roots, native dialogs, passkey prompts and browser chrome are outside this bridge.

## Protocol and validation

The MCP endpoint supports JSON-RPC initialization, ping, tool discovery and tool calls using protocol revision `2025-06-18`. Browser pipes carry bounded length-prefixed JSON; agent sockets carry bounded JSON lines. Requests expire without automatic replay, avoiding duplicate clicks after timeouts. Browser pipe closure revokes authority and removes its listening socket. Page contents and action logs are not persisted by the broker.

Regression tests use disposable homes, private sockets and synthetic pages. They check token rejection, role impersonation, disabled sessions, origin-bound grants, revocation races, timeouts, pipe teardown, relocation without an external Node, client configuration preservation and sensitive-field exclusion. Syntax checks use Chromium's real compiler and headers. Full engine linking and actual native browser checks remain separate gates; earlier extension checks do not qualify this implementation.
