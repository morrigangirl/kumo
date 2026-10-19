# Release preparation follow-up

This follows the earlier [development updater validation](github-release-updates.md).
Its original package identities, checks and evidence remain a historical snapshot.
The release under preparation is Kumo 0.1.0, build 202610190001.

The publisher now rejects a bundled model when its metadata explicitly records
both `included: true` and `localDevelopmentOnly: true`. Preparation checks this
before signing or notarization, production archive verification checks it again,
and signer activation checks before changing the staged configuration. The
guard does not infer a license or modify normal development packaging.

All **27 release tests and 64 package tests passed**, including six new
regressions. Tests cover the development-only model rejection, acceptance when
the model is absent, rejection while verifying an archived app, and unchanged
staging after rejected activation with or without a notarization request.
Official Sparkle archive and whole-feed signatures and tamper rejection remain
covered by the release suite.

The source publication review found no credentials, private keys, model weights,
generated apps, Chromium checkout, or personal drive paths in the release scope.
The unrelated historical Chrome promotion document is unchanged.

Production remains blocked by the missing Carson Press LLC Developer ID
Application identity, notarization setup and successful notarization, and the
explicit development-only status of the bundled PhishLang checkpoint. The model
must have that status resolved or be omitted from a separately verified package.
The current development app keeps update networking disabled.

The [machine-readable record](release-preparation.json) contains source and raw
evidence hashes for this follow-up. A GitHub preparation draft must remain
unpublished until it contains the final five verified release assets. Draft
notes must be reconciled with the exact final release notes before the guarded
publisher can complete it.
