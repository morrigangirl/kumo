# PhishLang for Kumo

An optional, separately installed Manifest V3 extension and native macOS companion.
The Kumo browser release does not contain this model. This add-on uses the pinned
PhishLang MobileBERT checkpoint locally through Swift/Core ML; it does not need
Python, a cloud AI account or an inference service on the user’s Mac.

## Install

Requires an Apple Silicon Mac running macOS 13 or later and Kumo. Extract the
complete add-on ZIP before running its commands.

1. Run `install.command` in the extracted folder. It installs the native companion
   to `~/Applications/Kumo PhishLang.app`, the extension to
   `~/Library/Application Support/KumoPhishLang/extension`, and the native host
   registration to Kumo’s user-level NativeMessagingHosts directory. It does not
   require administrator access.
2. In Kumo, open `chrome://extensions`, turn on **Developer mode**, choose
   **Load unpacked**, and select the installed extension folder above. In a file
   picker, Command-Shift-G opens **Go to Folder** so you can paste that path.
3. Open **Kumo PhishLang** from the extensions menu or its **Details →
   Extension options** page. Choose **Enable local warnings** and approve website
   access. Analysis starts off and remains off until you enable it.

Keep the installed extension folder. The extracted download can be moved after
installation. This developer-mode package is not a Chrome Web Store listing.

## What it does

The extension analyzes bounded public page text and control structure after a
page loads. A high score opens a warning that displays the site’s origin. **Leave this site**
replaces the warning with an empty tab; **Continue anyway** allows the returned document once.
Reloading can warn again. A low score means **no signal**, not that a site is safe.
The experimental model can make mistakes, including false positives on legitimate
sign-in pages. The threshold is not a calibrated probability of phishing.

Page analysis stays on the Mac. Filled form values, editable fields, scripts,
cookies, browser storage and Apple Passwords are excluded from model input.
Visible page text can still contain personal information. Private/incognito tabs,
Chrome Web Store pages and cross-origin frames are not scanned. Work and input
limits can leave part of a page unanalyzed. Analysis happens after load and does
not guarantee prevention of credential submission or malicious scripts.

This add-on does not control the browser for AI agents or replace Kumo’s known
malicious-domain blocking and download antivirus. It has its own extension ID,
settings, native host and installation. Turning it off unregisters its page
scanners and disconnects the model. Revoking website access also turns it off.

## Remove

Turn off the extension and remove it from `chrome://extensions`. Close Kumo, then
run `uninstall.command` from the extracted add-on folder to remove the companion,
installed extension files and its own native host registration. Other Kumo
settings, extensions, browser profiles and downloads are not removed.

## Build from this repository

Prepare the pinned model with `scripts/prepare-phishlang.py`, then run
`scripts/package-phishlang-extension.py --help` for packaging arguments. Prepared
model resources may be supplied with `--model-resources`; no upstream installer
or Python code is executed by the runtime. Packaging verifies the checkpoint and
conversion metadata, signs the companion with a selected local signing identity,
and runs real framed native inference before publishing the local output.

The companion uses CPU inference and a macOS sandbox without network access.
An 8 GB Mac remains an intended test target; the complete browser/add-on workload
has not yet been qualified on that hardware. The original model attribution,
source pin, conversion metadata and base MobileBERT license ship with the helper.
See [model provenance](../../native/phishing/NOTICE.md) for the recorded sources.
