# Native Chromium download protection

`kumo_download_guard.h/.mm` holds ordinary Chromium downloads for local antivirus scanning before completion or automatic opening. The source overlay preserves Chromium's quarantine and download lifecycle checks. See [download antivirus](../../docs/download-antivirus.md) for setup, failure behavior and limits.

Kumo's custom Apple Passwords context-menu action, native credential sheet, pairing components and SDK probes have been removed. Password extensions use Chromium's existing extension and native-messaging APIs. Chromium's own password-related APIs and WebAuthn remain available; this directory adds no password manager or credential bridge.
