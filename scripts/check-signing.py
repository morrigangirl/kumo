#!/usr/bin/env python3
"""Read public signing metadata for Kumo's selected team; never export keys."""
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
target = json.loads((ROOT / "config/apple-signing.json").read_text())
team = target["teamId"]
if not re.fullmatch(r"[A-Z0-9]{10}", team):
    raise SystemExit("Invalid selected Apple Developer Team ID.")
identities = subprocess.check_output(["security", "find-identity", "-v", "-p", "codesigning"], text=True)
valid = set(re.findall(r"\b[0-9A-F]{40}\b", identities))
pems = subprocess.check_output(["security", "find-certificate", "-a", "-p"], text=True)
certificates, seen = [], set()
for pem in re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pems, re.S):
    der = base64.b64decode("".join(pem.splitlines()[1:-1]))
    digest = hashlib.sha1(der).hexdigest().upper()
    if digest not in valid or digest in seen:
        continue
    seen.add(digest)
    subject = subprocess.check_output(["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"], input=pem, text=True).strip().removeprefix("subject=")
    values = dict(part.split("=", 1) for part in re.split(r"(?<!\\),", subject) if "=" in part)
    if values.get("OU") == team:
        name = values.get("CN", "")
        certificates.append({"identity": name, "developerIdApplication": name.startswith("Developer ID Application:")})

profiles = []
for folder in (Path.home()/"Library/Developer/Xcode/UserData/Provisioning Profiles", Path.home()/"Library/MobileDevice/Provisioning Profiles"):
    if not folder.is_dir():
        continue
    for file in folder.iterdir():
        if file.suffix not in (".provisionprofile", ".mobileprovision"):
            continue
        result = subprocess.run(["security", "cms", "-D", "-i", str(file)], capture_output=True)
        if result.returncode:
            continue
        try:
            profile = plistlib.loads(result.stdout)
        except Exception:
            continue
        entitlements = profile.get("Entitlements", {})
        app_id = entitlements.get("com.apple.application-identifier", entitlements.get("application-identifier"))
        if team in profile.get("TeamIdentifier", []) and app_id == team + "." + target["bundleIdentifier"]:
            profiles.append({"name": profile.get("Name"), "platforms": profile.get("Platform", []),
                             "expires": str(profile.get("ExpirationDate", "")),
                             "browserPasskeysApproved": entitlements.get(target["browserPasskeyEntitlement"]) is True})

print(json.dumps({"target": target, "validSigningIdentities": certificates,
                  "developerIdApplicationInstalled": any(c["developerIdApplication"] for c in certificates),
                  "matchingProfiles": profiles,
                  "note": "This checks public certificate/profile metadata only. Team selection does not grant entitlements or change the app's current signature."}, indent=2))
