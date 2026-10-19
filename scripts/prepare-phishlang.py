#!/usr/bin/env python3
"""Prepare Kumo's local-development PhishLang Core ML resources.

Only five immutable, hash-checked DATA files are fetched from upstream. No
upstream Python or installers are imported. Safetensors loading is explicit;
all Hugging Face lookups are offline. Python/torch are conversion tools only.

Run on Apple Silicon with Xcode installed:
  /usr/bin/python3 scripts/prepare-phishlang.py
The build-only Python 3.9 environment and all large artifacts stay in build/.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import statistics
import subprocess
import sys
import time
import urllib.request
import venv

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config/phishlang-model-lock.json"
BUILD = ROOT / "build/phishlang-model"
INPUT_NAMES = ("input_ids", "attention_mask", "token_type_ids")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def verified_data(path: Path, item: dict) -> bytes:
    data = path.read_bytes()
    blob = hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()
    if len(data) != item["bytes"] or blob != item["gitBlobSHA1"] or sha256(data) != item["sha256"]:
        raise RuntimeError(f"Pinned upstream data verification failed: {path.name}")
    return data


def download_inputs(lock: dict) -> Path:
    upstream = BUILD / "upstream"
    upstream.mkdir(parents=True, exist_ok=True)
    for item in lock["upstream"]["artifacts"]:
        destination = upstream / Path(item["path"]).name
        if not destination.exists():
            url = ("https://raw.githubusercontent.com/UTA-SPRLab/phishlang/"
                   + lock["upstream"]["commit"] + "/" + item["path"])
            temporary = destination.with_suffix(destination.suffix + ".download")
            try:
                request = urllib.request.Request(url, headers={"User-Agent": "Kumo-Model-Preparation/1"})
                with urllib.request.urlopen(request, timeout=120) as response:
                    data = response.read(item["bytes"] + 1)
                temporary.write_bytes(data)
                verified_data(temporary, item)
                temporary.replace(destination)
            finally:
                temporary.unlink(missing_ok=True)
        verified_data(destination, item)
    return upstream


def conversion_environment(lock: dict) -> Path:
    if sys.version_info[:2] != (3, 9):
        raise RuntimeError("The conversion wheel lock targets Python 3.9; use /usr/bin/python3 on this Mac.")
    environment = BUILD / "conversion-venv"
    executable = environment / "bin/python"
    if not executable.exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    requirements = BUILD / "conversion-requirements.txt"
    requirements.write_text("".join(
        f"{dep['name']}=={dep['version']} --hash=sha256:{dep['sha256']}\n"
        for dep in lock["conversion"]["dependencies"]
    ))
    # Binary-only and hash-checked: never run third-party source build hooks.
    subprocess.run([str(executable), "-m", "pip", "install", "--disable-pip-version-check",
                    "--only-binary=:all:", "--no-deps", "--require-hashes", "-r", str(requirements)], check=True)
    return executable


def directory_manifest(directory: Path) -> list:
    return [{"path": path.relative_to(directory).as_posix(),
             "bytes": path.stat().st_size, "sha256": sha256(path.read_bytes())}
            for path in sorted(directory.rglob("*")) if path.is_file()]


def convert_and_validate(lock: dict, upstream: Path) -> None:
    os.environ.update({"HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                       "TOKENIZERS_PARALLELISM": "false", "HF_HUB_DISABLE_TELEMETRY": "1"})
    import numpy as np
    import torch
    import coremltools as ct
    from transformers import MobileBertForSequenceClassification, MobileBertTokenizer

    for dep in lock["conversion"]["dependencies"]:
        if importlib.metadata.version(dep["name"]) != dep["version"]:
            raise RuntimeError(f"Conversion dependency drift: {dep['name']}")
    torch.set_num_threads(2)
    torch.manual_seed(0)
    settings = lock["conversion"]
    length = settings["windowSize"]
    started = time.monotonic()
    model = MobileBertForSequenceClassification.from_pretrained(
        upstream, local_files_only=True, use_safetensors=True).eval()
    tokenizer = MobileBertTokenizer.from_pretrained(upstream, local_files_only=True)

    class Logits(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def forward(self, input_ids, attention_mask, token_type_ids):
            return self.inner(input_ids=input_ids, attention_mask=attention_mask,
                              token_type_ids=token_type_ids, return_dict=False)[0]

    wrapped = Logits(model).eval()
    texts = [
        ("empty", ""),
        ("benign_article", 'TITLE: { "text": "Public library hours" } P: { "text": "Our library opens Monday at nine. Read books and attend community events." }'),
        ("login_structure", 'TITLE: { "text": "Example account sign in" } FORM: { "name": "login" } INPUT: { "type": "email", "name": "email", "placeholder": "Email address" } INPUT: { "type": "password", "name": "password" } BUTTON: { "text": "Sign in button" }'),
        ("urgent_structure", 'TITLE: { "text": "Account suspended" } P: { "text": "Urgent verify your account immediately to avoid closure." } LINK: { "text": "verify link", "href": "https://example.invalid/verify" }'),
        ("accented", 'TITLE: { "text": "Café déjà vu, naïve résumé, Ångström. İSTANBUL Straße Ελληνικά" }'),
        ("cjk", 'TITLE: { "text": "账户登录 日本語の銀行 中文安全測試 한글 로그인" }'),
        ("punctuation", 'LINK: { "text": "a/b?c=d&x=1 link", "href": "https://example.invalid:8443/a_b?q=redacted" }'),
        ("whitespace", 'TITLE:\t{\r\n "text": "Hello\u00a0world\u2003next\x00\x07" }'),
        ("long_truncated", 'P: { "text": "' + "hello community library " * 120 + '" }'),
        ("long_unknown_word", 'P: { "text": "' + "a" * 101 + '" }'),
    ]
    encoded = tokenizer(texts[1][1], padding="max_length", truncation=True,
                        max_length=length, return_tensors="pt")
    example = tuple(encoded[name].to(torch.int32) for name in INPUT_NAMES)
    print("Tracing pinned MobileBERT with fixed [1,128] int32 inputs...", flush=True)
    with torch.inference_mode():
        traced = torch.jit.trace(wrapped, example)
    converted = ct.convert(
        traced, convert_to="mlprogram", minimum_deployment_target=ct.target.macOS13,
        compute_units=ct.ComputeUnit.CPU_ONLY, compute_precision=ct.precision.FLOAT32,
        inputs=[ct.TensorType(name=name, shape=(1, length), dtype=np.int32) for name in INPUT_NAMES],
        outputs=[ct.TensorType(name="logits", dtype=np.float32)], skip_model_load=True)
    converted.short_description = "PhishLang MobileBERT classifier, local Kumo development port"
    converted.version = lock["upstream"]["commit"]
    converted.user_defined_metadata["rights_status"] = lock["rights"]["status"]
    converted.user_defined_metadata["local_development_only"] = "true"
    package = BUILD / "PhishLang.mlpackage"
    if package.exists():
        shutil.rmtree(package)
    converted.save(str(package))
    compile_directory = BUILD / "compiled"
    compile_directory.mkdir(exist_ok=True)
    compiled = compile_directory / "PhishLang.mlmodelc"
    if compiled.exists():
        shutil.rmtree(compiled)
    subprocess.run(["xcrun", "coremlcompiler", "compile", str(package), str(compile_directory)], check=True)
    runtime = ct.models.CompiledMLModel(str(compiled), compute_units=ct.ComputeUnit.CPU_ONLY)
    results = []
    for name, text in texts:
        features = tokenizer(text, padding="max_length", truncation=True,
                             max_length=length, return_tensors="pt")
        args = tuple(features[key].to(torch.int32) for key in INPUT_NAMES)
        with torch.inference_mode():
            expected = wrapped(*args).detach().numpy()
        before = time.monotonic()
        observed = np.asarray(runtime.predict({key: features[key].numpy().astype(np.int32)
                                               for key in INPUT_NAMES})["logits"])
        duration = time.monotonic() - before
        if expected.shape != (1, 2) or observed.shape != (1, 2):
            raise RuntimeError("Unexpected classifier output shape")
        if not np.isfinite(observed).all():
            raise RuntimeError("Non-finite Core ML output")
        difference = float(np.max(np.abs(expected - observed)))
        def probability(logits):
            values = np.exp(logits - np.max(logits))
            return float(values[0, 1] / np.sum(values))
        expected_probability, observed_probability = probability(expected), probability(observed)
        probability_difference = abs(expected_probability - observed_probability)
        logits_match = bool(np.allclose(expected, observed,
            atol=settings["logitAbsoluteTolerance"], rtol=settings["logitRelativeTolerance"]))
        if not logits_match or probability_difference > settings["phishingProbabilityAbsoluteTolerance"]:
            raise RuntimeError(f"Core ML parity failed for {name}: {difference=}, {probability_difference=}")
        results.append({"name": name, "text": text, "pytorchLogits": expected.tolist(),
                        "coremlLogits": observed.tolist(), "maxAbsoluteDifference": difference,
                        "pytorchPhishingProbability": expected_probability,
                        "coremlPhishingProbability": observed_probability,
                        "phishingProbabilityDifference": probability_difference,
                        "coremlCPUSeconds": duration})
    reference_texts = texts + [
        ("special_tokens", "[CLS] [SEP] [UNK] [PAD] [MASK]"),
        ("mixed_unicode", "Café\u0301 résumé\u00a0A\u2003B\tC\nD\rE 中\U00020000文 naïve don't foo_bar 123.45 😀"),
        ("word_boundary_100", "a" * 100),
        ("word_boundary_101", "a" * 101),
        ("combining_and_controls", "A\u0301 e\u0308\u200bfoo\ufeffbar\x00\x01 baz\ufffd end"),
        ("control_private_unassigned", "a\x0bb\x0cc\ue000d\u0378e"),
    ]
    references = []
    for name, text in reference_texts:
        tokens = tokenizer.tokenize(text)
        ids = tokenizer.convert_tokens_to_ids(tokens)
        fixed = tokenizer(text, padding="max_length", truncation=True, max_length=length)
        references.append({"name": name, "text": text, "tokens": tokens, "ids": ids,
                           "input_ids": fixed["input_ids"], "attention_mask": fixed["attention_mask"],
                           "token_type_ids": fixed["token_type_ids"]})
    write_json(BUILD / "tokenizer-reference.json", {
        "schemaVersion": 1, "sourceCommit": lock["upstream"]["commit"],
        "tokenizerClass": "MobileBertTokenizer", "transformersVersion": "4.44.0",
        "specialTokenIDs": {key: getattr(tokenizer, key + "_token_id")
                            for key in ("pad", "unk", "cls", "sep", "mask")},
        "cases": references})
    destination = BUILD / "PhishLang.mlmodelc"
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(compiled, destination)
    shutil.copyfile(upstream / "vocab.txt", BUILD / "vocab.txt")
    manifest = directory_manifest(destination)
    directory_digest = sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    info = {
        "schemaVersion": 1, "modelVersion": lock["upstream"]["commit"],
        "sourceCommit": lock["upstream"]["commit"], "upstreamRepository": lock["upstream"]["repository"],
        "modelName": "PhishLang-MobileBERT", "windowSize": length, "stride": settings["stride"],
        "maxWindows": settings["maxWindows"], "classIndex": settings["classIndex"],
        "computeUnits": "cpuOnly", "precision": "FLOAT32", "minimumMacOS": "13.0",
        "localDevelopmentOnly": True, "rightsStatus": lock["rights"]["status"],
        "paperLicense": "CC-BY-4.0", "paperLicenseDoesNotEstablishArtifactLicense": True,
        "upstreamSafetensorsSHA256": next(x["sha256"] for x in lock["upstream"]["artifacts"] if x["path"].endswith("model.safetensors")),
        "vocabSHA256": sha256((BUILD / "vocab.txt").read_bytes()),
        "modelDirectorySHA256": directory_digest, "modelFiles": manifest,
        "inputs": [{"name": name, "type": "int32", "shape": [1, length]} for name in INPUT_NAMES],
        "output": {"name": "logits", "type": "float32", "shape": [1, 2]},
        "conversionLockSHA256": sha256(LOCK_PATH.read_bytes()),
        "validation": {"syntheticCaseCount": len(results), "passed": True,
                       "maxLogitAbsoluteDifference": max(x["maxAbsoluteDifference"] for x in results),
                       "maxProbabilityAbsoluteDifference": max(x["phishingProbabilityDifference"] for x in results)},
    }
    write_json(BUILD / "model-info.json", info)
    write_json(BUILD / "conversion-report.json", {
        "schemaVersion": 1, "passed": True, "sourceCommit": lock["upstream"]["commit"],
        "conversionLockSHA256": info["conversionLockSHA256"], "modelDirectorySHA256": directory_digest,
        "sourceArtifacts": lock["upstream"]["artifacts"], "dependencies": lock["conversion"]["dependencies"],
        "pythonVersion": platform.python_version(), "macOSVersion": platform.mac_ver()[0],
        "machine": platform.machine(), "computeUnits": "CPU_ONLY", "precision": "FLOAT32",
        "logitAbsoluteTolerance": settings["logitAbsoluteTolerance"],
        "logitRelativeTolerance": settings["logitRelativeTolerance"],
        "probabilityAbsoluteTolerance": settings["phishingProbabilityAbsoluteTolerance"],
        "cases": results, "medianCPUInferenceSeconds": statistics.median(x["coremlCPUSeconds"] for x in results),
        "modelBytes": sum(x["bytes"] for x in manifest), "conversionPeakRSSBytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "elapsedSeconds": time.monotonic() - started,
        "limits": ["Synthetic numerical parity verifies conversion, not phishing accuracy or calibration.",
                   "Conversion Python peak memory is not native runtime memory.",
                   "8 GB minimum hardware has not been directly qualified by this conversion test.",
                   "The pinned upstream code and model weights have no explicit artifact redistribution license."],
        "reproduce": "/usr/bin/python3 scripts/prepare-phishlang.py",
    })
    print(f"Validated {len(results)} CPU Core ML cases; model resources ready in {BUILD}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--conversion-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--verify-only", action="store_true", help="Verify pinned upstream input files without installing or converting")
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64":
        raise RuntimeError("Core ML preparation requires an Apple Silicon Mac.")
    BUILD.mkdir(parents=True, exist_ok=True)
    lock = json.loads(LOCK_PATH.read_text())
    upstream = download_inputs(lock)
    if args.verify_only:
        print("Pinned upstream Safetensors and tokenizer data verified.")
    elif args.conversion_worker:
        convert_and_validate(lock, upstream)
    else:
        executable = conversion_environment(lock)
        subprocess.run([str(executable), str(Path(__file__).resolve()), "--conversion-worker"], check=True)


if __name__ == "__main__":
    main()
