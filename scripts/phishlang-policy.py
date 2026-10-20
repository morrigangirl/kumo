#!/usr/bin/env python3
"""Project distribution decisions, separate from upstream model provenance.

This policy records the project owner's accepted interpretation. It neither
creates an upstream license grant nor rewrites the original conversion metadata.
"""
import datetime
import hashlib
import json
from pathlib import Path

DECISION_FIELDS = {
    "schemaVersion", "status", "acceptedOn", "scope", "interpretedLicense", "basisURL",
    "upstreamConfirmation", "sourceRepository", "sourceCommit", "upstreamSafetensorsSHA256",
    "attributionRequired", "paperURL",
}
STATUS = "owner-accepted-project-interpretation"
PAPER = "https://arxiv.org/abs/2408.05667"


def decision_sha256(decision):
    return hashlib.sha256(json.dumps(decision, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_decision(root, required=False):
    path = Path(root) / "config/phishlang-distribution.json"
    if not path.exists() and not path.is_symlink():
        if required:
            raise RuntimeError("An included PhishLang model requires an explicit accepted project distribution decision.")
        return None
    try:
        if path.is_symlink() or path.stat().st_size > 16_384:
            raise ValueError("Invalid decision file")
        value = json.loads(path.read_text())
        lock = json.loads((Path(root) / "config/phishlang-model-lock.json").read_text())
        weights = next(item["sha256"] for item in lock["upstream"]["artifacts"] if item["path"] == "src/model/model.safetensors")
        if not isinstance(value, dict) or set(value) != DECISION_FIELDS:
            raise ValueError("Unexpected decision fields")
        expected = {
            "schemaVersion": 1, "status": STATUS, "scope": "kumo-browser-public-distribution",
            "interpretedLicense": "CC-BY-4.0", "basisURL": PAPER, "paperURL": PAPER,
            "upstreamConfirmation": False, "attributionRequired": True,
            "sourceRepository": lock["upstream"]["repository"], "sourceCommit": lock["upstream"]["commit"],
            "upstreamSafetensorsSHA256": weights,
        }
        for key, item in expected.items():
            if value.get(key) != item or type(value.get(key)) is not type(item):
                raise ValueError("Decision does not match the pinned checkpoint or owner interpretation")
        accepted = value["acceptedOn"]
        if not isinstance(accepted, str) or datetime.date.fromisoformat(accepted).isoformat() != accepted:
            raise ValueError("Invalid acceptance date")
        return value
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        raise RuntimeError("PhishLang project distribution decision is invalid or differs from the pinned checkpoint.") from error


def model_metadata(info, root):
    """Preserve source facts and record effective project policy explicitly."""
    result = {
        "sourceCommit": info["sourceCommit"], "upstreamSafetensorsSHA256": info["upstreamSafetensorsSHA256"],
        "modelLocalDevelopmentOnly": info.get("localDevelopmentOnly") is True,
        "localDevelopmentOnly": info.get("localDevelopmentOnly") is True,
        "rightsStatus": info.get("rightsStatus", "unverified"),
    }
    decision = load_decision(root)
    if decision is not None:
        if (info["sourceCommit"] != decision["sourceCommit"] or info["modelVersion"] != decision["sourceCommit"] or
                info["upstreamSafetensorsSHA256"] != decision["upstreamSafetensorsSHA256"]):
            raise RuntimeError("PhishLang model differs from the accepted project distribution decision.")
        result.update({"localDevelopmentOnly": False, "distributionDecision": decision,
                       "distributionDecisionSHA256": decision_sha256(decision)})
    return result


def validate_public_model_scope(build, root):
    if not isinstance(build, dict):
        raise RuntimeError("App build metadata must be a dictionary.")
    phishing = build.get("phishingProtection")
    if not isinstance(phishing, dict) or phishing.get("included") is not True:
        return
    # Keep the existing development-only guard. Flipping a boolean is not a
    # license decision: every included production model also needs the exact
    # tracked, checkpoint-bound owner decision below.
    if phishing.get("localDevelopmentOnly") is True:
        raise RuntimeError("Bundled PhishLang metadata declares localDevelopmentOnly=true; "
                           "a public production release cannot include this development-only model without an explicit accepted project distribution decision.")
    decision = load_decision(root, required=True)
    if (phishing.get("localDevelopmentOnly") is not False or
            type(phishing.get("modelLocalDevelopmentOnly")) is not bool or
            not isinstance(phishing.get("distributionDecision"), dict) or
            phishing.get("distributionDecision") != decision or
            decision_sha256(phishing["distributionDecision"]) != decision_sha256(decision) or
            phishing.get("distributionDecisionSHA256") != decision_sha256(decision) or
            phishing.get("sourceCommit") != decision["sourceCommit"] or
            phishing.get("modelVersion") != decision["sourceCommit"] or
            phishing.get("upstreamSafetensorsSHA256") != decision["upstreamSafetensorsSHA256"]):
        raise RuntimeError("Included PhishLang production metadata does not match the explicit accepted pinned-checkpoint distribution decision.")
