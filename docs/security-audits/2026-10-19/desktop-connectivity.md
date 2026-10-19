# Desktop browser-agent connectivity

Kumo's setup now configures **Codex Desktop and Claude Desktop** through local stdio MCP. The previous generated commands embedded the developer checkout path and targeted Claude Code. New commands locate Kumo by its macOS application identifier, and client configuration starts an independent private runtime in `~/.kumo/agents/server/`.

## Changes

- Setup commands contain no checkout path, application installation path, username or pinned Node binary path.
- The native launcher accepts four fixed setup actions, invokes helpers relative to its own bundle and rejects additional setup arguments. It does not forward those actions to Chromium.
- The installed launcher finds Node 22+ at runtime, binds its broker runtime to its own directory and keeps stdout exclusively for MCP. Removing the original checkout does not break it.
- Codex registration uses the official CLI, discovered in PATH or supported desktop application bundles. Caller-selected `CODEX_HOME` is preserved and validated.
- Claude Desktop registration updates its actual local JSON configuration, preserving other entries. Both installers retain private original backups. No provider credentials are imported or logged, and setup does not restart a client.
- Chromium loads its writable rule cache from a verified versioned extension copy in the private browser profile, preserving the sealed application resources.
- Packaging copies only the eight approved bridge runtime files. Local environment files, pairing tokens and other extras are excluded.
- Published historical audit exports have machine-specific checkout paths normalized. Their original bytes and hashes remain available privately; evidence hashes retain their original scope.

## Validation

The full JavaScript suite passed **147 tests**, including **23 bridge tests** and thirteen new Desktop installation/relocation cases. The native launcher passed **13 compiled tests**, including three setup-dispatch tests after moving a synthetic bundle into a directory containing spaces and shell characters. Runtime-copy tests cover private modes, concurrent atomic publication, cache reuse, source changes, tampering and symlink parents. Package guards passed **53 tests**, including rejection of symlinked bridge code and exclusion of local secret fixtures and generated caches from sealed resources.

Final review found and corrected the backup boundary for an existing configuration in a safe external `CODEX_HOME`. The regression verifies the exact private backup, unrelated server preservation and portable registration without creating the default Codex directory. The installed runtime was refreshed without changing either client's configuration.

On this development Mac, both installed Desktop client configurations were updated and checked against their private backups. Unrelated effective settings were preserved. The official Codex CLI omitted one unrelated empty stdio argument list during serialization; omitted arguments and an empty list have the same meaning.

The exact installed Desktop stdio command was launched from an unrelated temporary working directory. MCP initialization and all eight browser tools were discovered; an ungranted snapshot request was denied, with no non-protocol stdout. Provider accounts and personal pages were not used for this proof. Codex Desktop subsequently loaded all eight Kumo tools in the active chat. A live `browser_tabs` invocation returned the expected “open Kumo and enable agent control” response while no browser was connected. Claude Desktop registration and its identical stdio command were verified; its UI/tool reload was not exercised. Reload MCP connections or restart Claude Desktop to load the new server.

A later probe found Claude's registration absent after its configuration file changed. The writer was not identified. Kumo's entry was restored while Claude was closed, preserving the current unrelated settings and making another private backup. The refreshed installed command again passed MCP initialization, eight-tool discovery and ungranted-access denial. Normal instructions now specify fully quitting Claude before setup and opening it afterward. This checks registration and transport; Claude's own tool UI still requires verification after launch.

Private raw evidence is under `.cache/qa/desktop-connectivity-2026-10-19/` and `.cache/qa/desktop-agent-portability-2026-10-19/`. Files containing local configuration paths remain outside Git. See [Desktop setup and access boundaries](../../agents.md) for normal use.

The connection supplies Kumo's opt-in `browser_*` MCP tools. The clients' separate built-in Chrome computer-use integrations are outside this registration. Existing origin-bound grants, revocation, sensitive-field exclusions and local socket authentication remain enforced.
