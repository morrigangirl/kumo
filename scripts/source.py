#!/usr/bin/env python3
"""Prepare and compile the pinned Chromium source fork on macOS arm64.

No Chromium source download occurs for doctor, self-test, or --dry-run.
"""
from __future__ import annotations

import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "config/source-lock.json"
GN_PATH = ROOT / "config/chromium.gn"
VENDOR = ROOT / "vendor/ungoogled-chromium-macos"
INTEGRATION_OVERLAYS = ("native_overlay.py", "extensions_overlay.py", "malware_overlay.py")
DOWNLOAD_GUARD_INPUTS = ("kumo_download_guard.h", "kumo_download_guard.mm")


def run(*command, cwd=None, env=None):
    print("+ " + shlex.join(str(arg) for arg in command), flush=True)
    subprocess.run([str(arg) for arg in command], cwd=cwd, env=env, check=True)


def output(*command):
    return subprocess.check_output([str(arg) for arg in command], text=True).strip()


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_file(path, expected):
    if digest(path) != expected:
        raise RuntimeError(f"Checksum mismatch: {path}")


def lock_data():
    lock = json.loads(LOCK_PATH.read_text())
    if lock["schema"] != 1 or lock["targetCpu"] != "arm64":
        raise RuntimeError("Unsupported source lock schema or target")
    return lock


def core_vendor(lock):
    """Keep platform packaging and common security patch pins independent."""
    relative = lock["ungoogledChromium"].get("path")
    return (ROOT / relative).resolve() if relative else VENDOR / "ungoogled-chromium"


def verify_vendor(lock):
    for folder, expected in ((VENDOR, lock["macosPackaging"]["commit"]),
                             (core_vendor(lock), lock["ungoogledChromium"]["commit"])):
        if not (folder / ".git").exists():
            raise RuntimeError(f"Missing pinned checkout: {folder}. See docs/source-build.md.")
        if output("git", "-C", folder, "rev-parse", "HEAD") != expected:
            raise RuntimeError(f"Unexpected upstream revision: {folder}")
        if output("git", "-C", folder, "status", "--porcelain", "--untracked-files=normal"):
            raise RuntimeError(f"Upstream checkout has local changes: {folder}. Keep overlays outside vendor.")
    version = (core_vendor(lock) / "chromium_version.txt").read_text().strip()
    if version != lock["chromiumVersion"]:
        raise RuntimeError("Chromium version does not match source lock")


def doctor(lock, strict=True):
    errors = []
    print(f"Host: {platform.system()} {platform.release()} / {platform.machine()}")
    if sys.platform != "darwin" or platform.machine() != "arm64":
        errors.append("An Apple Silicon Mac is required for this source target.")
    if sys.version_info < (3, 10):
        errors.append("Python 3.10+ is required.")
    print(f"Python: {platform.python_version()}")
    for name in ("git", "patch", "ninja", "node", "npm", "go", "esbuild", "tsc",
                 "greadlink", "perl", "codesign", "xcodebuild", "xcrun", "zstd"):
        found = shutil.which(name)
        print(f"{name}: {found or 'MISSING'}")
        if not found:
            errors.append(f"Missing build tool: {name}")
    # The pinned platform patches use these exact Homebrew paths.
    for path in ("/opt/homebrew/bin/esbuild", "/opt/homebrew/bin/tsc"):
        if not Path(path).is_file():
            errors.append(f"Pinned upstream patches require {path}.")
    if shutil.which("xcrun"):
        try:
            print("macOS SDK: " + output("xcrun", "--sdk", "macosx", "--show-sdk-version"))
            print("Xcode: " + output("xcodebuild", "-version").replace("\n", "; "))
        except subprocess.CalledProcessError:
            errors.append("Full Xcode must be selected with xcode-select and its license accepted.")
    free = shutil.disk_usage(ROOT).free / (1024 ** 3)
    print(f"Workspace disk available: {free:.1f} GiB (allow 220+ GiB for source, tools, cache and output)")
    if free < 220:
        print("WARNING: Available disk may be insufficient for a complete build.")
    try:
        verify_vendor(lock)
        print("Pinned upstream revisions: verified clean")
    except (RuntimeError, subprocess.CalledProcessError) as error:
        errors.append(str(error))
    for error in errors:
        print("ERROR: " + error, file=sys.stderr)
    if errors and strict:
        raise RuntimeError("Source-build prerequisites are incomplete; no source was downloaded.")
    return not errors


def merge_gn(*texts):
    """Merge simple upstream assignments without duplicate GN definitions."""
    assignments = {}
    for text in texts:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            match = re.fullmatch(r"([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*(.+)", line)
            if not match:
                raise RuntimeError(f"Review unsupported GN input: {line}")
            assignments[match[1]] = match[2]
    return "# Generated by scripts/source.py; edit config/chromium.gn.\n" + "".join(
        f"{key} = {value}\n" for key, value in assignments.items())


def bindgen_environment(src, build_env):
    """Use the SDK's compatible linker and pinned Rust libs for this host tool."""
    linker = output("xcrun", "--find", "ld")
    if not Path(linker).is_file() or any(character.isspace() for character in linker):
        raise RuntimeError("Expected an Xcode linker path without whitespace")
    rust_lib = src / "third_party/rust-toolchain/rustc/lib"
    if not (rust_lib / "libLLVM.dylib").is_file():
        raise RuntimeError("Missing pinned Rust libLLVM for the bindgen host build")
    result = build_env.copy()
    # Upstream appends -fuse-ld=lld. Clang's explicit --ld-path takes precedence
    # while preserving all of the helper's other compiler and linker options.
    result["RUSTFLAGS"] = result.get("RUSTFLAGS", "") + f" -Clink-arg=--ld-path={linker}"
    result["LDFLAGS"] = result.get("LDFLAGS", "") + f" --ld-path={linker}"
    result["DYLD_LIBRARY_PATH"] = str(rust_lib)
    return result


def compatibility_linker(src, lock, verify_only=False):
    """Keep the SDK-compatible release linker separate from pinned compilers."""
    spec = importlib.util.spec_from_file_location(
        "_kumo_verified_linker", ROOT / "scripts/verified_lld.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load locked compatibility-linker helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    settings = lock["compatibilityLinker"]
    if verify_only:
        return module.verify_linker(src, settings)
    return module.ensure_linker(src, ROOT, settings)


def enterprise_profile_compatibility(src):
    """Cancel the test-only caller of an intentionally omitted sign-in controller."""
    path = src / "chrome/browser/enterprise/signin/profile_management_disclaimer_service.cc"
    data = path.read_bytes()
    expected = "881817855117a9abf0b487f9113ef3a9b62d841b4d4305565403b43d10b53991"
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("Enterprise sign-in compatibility preimage changed; review before applying")
    text = data.decode("utf-8")
    old = """  if (profile_separation_policies_for_testing_.has_value() ||
      user_choice_for_testing_.has_value()) {
    CHECK_IS_TEST();
    state_->profile_creation_controller =
        ManagedProfileCreationController::CreateManagedProfileForTesting(
            &profile_.get(), GetExtendedAccountInfo(state_->account_id),
            // The access point always has a value if the account_id is set.
            *state_->access_point,
            base::BindOnce(&ProfileManagementDisclaimerService::
                               OnManagedProfileCreationResult,
                           weak_ptr_factory_.GetWeakPtr()),
            profile_separation_policies_for_testing_,
            user_choice_for_testing_);
    return;
  }
"""
    new = """  if (profile_separation_policies_for_testing_.has_value() ||
      user_choice_for_testing_.has_value()) {
    CHECK_IS_TEST();
    // KUMO_ENTERPRISE_PROFILE_COMPATIBILITY_V1
    // Browser-account profile creation is disabled by the pinned ungoogled
    // patches. Decline this test-only request through the existing reset path.
    state_->profile_to_continue_in = nullptr;
    Reset();
    return;
  }
"""
    if text.count(old) != 1:
        raise RuntimeError("Enterprise sign-in testing branch changed")
    patched = text.replace(old, new).encode("utf-8")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".kumo-signin-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(patched)
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def brand_source(src):
    branding = src / "chrome/app/theme/chromium/BRANDING"
    text = branding.read_text()
    replacements = {"PRODUCT_SHORTNAME": "Kumo", "PRODUCT_INSTALLER_FULLNAME": "Kumo Installer",
                    "PRODUCT_INSTALLER_SHORTNAME": "Kumo Installer", "MAC_BUNDLE_ID": "app.kumo.browser.engine"}
    for key, value in replacements.items():
        text, count = re.subn(rf"(?m)^{key}=.*$", f"{key}={value}", text)
        if count != 1:
            raise RuntimeError(f"Upstream BRANDING changed: {key}")
    branding.write_text(text)
    strings = src / "chrome/app/chromium_strings.grd"
    text = strings.read_text()
    for name in ("IDS_PRODUCT_NAME", "IDS_SHORT_PRODUCT_NAME", "IDS_ACCNAME_APP",
                 "IDS_FIRST_RUN_DIALOG_WINDOW_TITLE", "IDS_TASK_MANAGER_TITLE"):
        pattern = rf'(<message\b[^>]*\bname="{name}"[^>]*>)(.*?)(</message>)'
        def replace(match):
            return match[1] + match[2].replace("Chromium", "Kumo") + match[3]
        text, count = re.subn(pattern, replace, text, flags=re.DOTALL)
        if not count:
            raise RuntimeError(f"Upstream application string changed: {name}")
    strings.write_text(text)
    # Website identity is separate from browser-account identity. Preserve the
    # standards API used by modern Sign in with Google flows, without sync keys.
    features = src / "content/public/common/content_features.cc"
    text = features.read_text()
    text, count = re.subn(r'(BASE_FEATURE\(kFedCm,\s*)base::FEATURE_DISABLED_BY_DEFAULT(\);)',
                         r'\1base::FEATURE_ENABLED_BY_DEFAULT\2', text)
    if count != 1:
        raise RuntimeError("Upstream FedCM patch changed; review website authentication compatibility")
    features.write_text(text)
    # Keep the real Store origins isolated even though internal Store service
    # integration stays disabled. This requests no Google network connection.
    extensions = src / "chrome/browser/extensions/chrome_content_browser_client_extensions_part.cc"
    text = extensions.read_text()
    marker = "GetOriginsRequiringDedicatedProcess() {\n  std::vector<url::Origin> list;"
    if text.count(marker) != 1:
        raise RuntimeError("Upstream Store process-isolation hook changed")
    text = text.replace(marker, marker + '\n  list.push_back(url::Origin::Create(GURL("https://chrome.google.com")));'
                        + '\n  list.push_back(url::Origin::Create(GURL("https://chromewebstore.google.com")));')
    extensions.write_text(text)


def verify_integration_inputs():
    """Fail before retrieval if an integration or its copied source is absent."""
    for name in INTEGRATION_OVERLAYS:
        path = ROOT / "scripts" / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Missing Chromium integration overlay: {name}; no source downloaded")
    for name in DOWNLOAD_GUARD_INPUTS:
        path = ROOT / "native/chromium" / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"Missing native download security input: {name}; no source downloaded")


def input_digest():
    verify_integration_inputs()
    h = hashlib.sha256()
    paths = [LOCK_PATH, GN_PATH, Path(__file__)]
    for name in (*INTEGRATION_OVERLAYS, "build_receipt.py", "verified_lld.py"):
        overlay = ROOT / "scripts" / name
        if overlay.is_file():
            paths.append(overlay)
    paths.extend(sorted((ROOT / "native/chromium").glob("*")))
    for path in paths:
        if path.is_file():
            h.update(str(path.relative_to(ROOT)).encode())
            h.update(path.read_bytes())
    return h.hexdigest()


def create_recipe(work, lock):
    recipe = work / "recipe"
    shutil.copytree(VENDOR, recipe, ignore=shutil.ignore_patterns(".git", "build", "__pycache__", "*.pyc"))
    # A newer common security patch set can be ported without mutating the
    # pinned macOS packaging checkout or its recorded older submodule.
    common = core_vendor(lock)
    if common.resolve() != (VENDOR / "ungoogled-chromium").resolve():
        shutil.rmtree(recipe / "ungoogled-chromium")
        shutil.copytree(common, recipe / "ungoogled-chromium",
                        ignore=shutil.ignore_patterns(".git", "build", "__pycache__", "*.pyc"))
    # Keep verified archives outside the mutable recipe/source workspace so a
    # failed patch or refreshed overlay never requires downloading them again.
    cache = ROOT / ".cache/source-downloads"
    cache.mkdir(parents=True, exist_ok=True)
    (recipe / "build").mkdir()
    (recipe / "build/download_cache").symlink_to(cache, target_is_directory=True)
    # The archive's official hashes are additionally pinned here. The upstream
    # downloader checks these before unpacking, including already-cached files.
    for relative, section, item in (("ungoogled-chromium/downloads.ini", "chromium", "sourceArchive"),
                                    ("downloads-arm64.ini", "rust", "rustArchive")):
        path = recipe / relative
        ini = configparser.ConfigParser(defaults={"_chromium_version": lock["chromiumVersion"]})
        ini.read(path)
        if ini.get(section, "url") != lock[item]["url"]:
            raise RuntimeError(f"Pinned upstream resource URL changed: {section}")
        ini.set(section, "sha256", lock[item]["sha256"])
        # ConfigParser writes interpolation values literally, as upstream expects.
        with path.open("w") as handle:
            ini.write(handle)
    # Download quarantine is an OS security boundary, not a Google service.
    # Keep Chromium's original source and its quarantine service dependency.
    series = recipe / "ungoogled-chromium/patches/series"
    patch = "extra/ungoogled-chromium/disable-download-quarantine.patch"
    lines = series.read_text().splitlines()
    if lines.count(patch) != 1:
        raise RuntimeError("Upstream quarantine patch selection changed")
    series.write_text("\n".join(line for line in lines if line != patch) + "\n")
    return recipe


def save_state(work, state):
    path = work / "state.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n")
    temporary.replace(path)


def prepare(work, lock):
    verify_integration_inputs()
    verify_vendor(lock)
    work.mkdir(parents=True, exist_ok=True)
    state_path = work / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"inputDigest": input_digest(), "done": []}
    if state["inputDigest"] != input_digest():
        raise RuntimeError("Source recipe changed. Use a new --work-dir to preserve the old source tree.")
    if state.get("inProgress") in ("source", "platform"):
        # Source extraction precedes all source mutations. Platform retrieval
        # clears/recreates only its own toolchain directories. Both can safely
        # restart using cached archives, which upstream verifies again.
        interrupted = state.pop("inProgress")
        print(f"Resuming interrupted {interrupted} retrieval from the verified archive cache.")
        save_state(work, state)
    elif state.get("inProgress"):
        raise RuntimeError(f"Source stage {state['inProgress']} was interrupted. Use a new --work-dir; partial patching is never retried.")
    if "ready" in state["done"]:
        if "malware-downloads" not in state["done"]:
            raise RuntimeError("Prepared source is missing its native malware download stage; use a new --work-dir.")
        compatibility_linker(work / "recipe/build/src", lock)
        print(f"Prepared source: {work / 'recipe/build/src'}")
        return
    if not state_path.exists():
        if (work / "recipe").exists():
            raise RuntimeError("Unrecorded recipe directory exists; use a new --work-dir.")
        create_recipe(work, lock)
        save_state(work, state)
    recipe = work / "recipe"
    main = recipe / "ungoogled-chromium"
    src = recipe / "build/src"
    def stage(name, action):
        if name in state["done"]:
            return
        state["inProgress"] = name
        save_state(work, state)
        action()
        state["done"].append(name)
        state.pop("inProgress")
        save_state(work, state)
    stage("source", lambda: run(sys.executable, recipe / "retrieve_and_unpack_resource.py", "-d", "-g", "arm64"))
    stage("prune", lambda: run(sys.executable, main / "utils/prune_binaries.py", src, main / "pruning.list"))
    stage("patch", lambda: run(sys.executable, main / "utils/patches.py", "apply", src, main / "patches", recipe / "patches"))
    stage("domains", lambda: run(sys.executable, main / "utils/domain_substitution.py", "apply", "-r", main / "domain_regex.list", "-f", main / "domain_substitution.list", src))
    stage("enterprise-profile-compatibility", lambda: enterprise_profile_compatibility(src))
    stage("platform", lambda: run(sys.executable, recipe / "retrieve_and_unpack_resource.py", "-p", "arm64"))
    stage("compatible-linker", lambda: compatibility_linker(src, lock))
    stage("branding", lambda: brand_source(src))
    stage("native-passwords", lambda: run(sys.executable, ROOT / "scripts/native_overlay.py", src))
    stage("extensions", lambda: run(sys.executable, ROOT / "scripts/extensions_overlay.py", src))
    stage("malware-downloads", lambda: run(sys.executable, ROOT / "scripts/malware_overlay.py", src))
    def configure():
        destination = src / "out/Default"
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "args.gn").write_text(merge_gn((main / "flags.gn").read_text(),
            (recipe / "flags.macos.gn").read_text(), GN_PATH.read_text()))
    stage("gn-arguments", configure)
    stage("ready", lambda: None)
    print(f"Prepared Chromium {lock['chromiumVersion']} source: {src}\nCompilation has not run.")


def build(work, lock, jobs):
    doctor(lock)
    prepare(work, lock)
    recipe = work / "recipe"
    src = recipe / "build/src"
    app = src / lock["engineBundle"]
    args_path = src / "out/Default/args.gn"
    expected_args = merge_gn((recipe / "ungoogled-chromium/flags.gn").read_text(),
                             (recipe / "flags.macos.gn").read_text(), GN_PATH.read_text())
    linker_arg = 'lld_path = "//' + lock["compatibilityLinker"]["relativePath"] + '/bin"\n'
    if linker_arg not in expected_args or "use_lld = true\n" not in expected_args:
        raise RuntimeError("Locked GN arguments do not select the verified compatibility linker")
    if args_path.read_text() != expected_args:
        raise RuntimeError("Prepared GN arguments differ from the locked configuration; no compilation started")
    # A prepared-state label alone cannot attest that the mandatory completion
    # hook and copied native guard still match the reviewed repository inputs.
    run(sys.executable, ROOT / "scripts/malware_overlay.py", src, "--verify-applied")
    built_args = digest(args_path)
    build_inputs = input_digest()
    receipt_spec = importlib.util.spec_from_file_location("_kumo_completed_build", ROOT / "scripts/build_receipt.py")
    if receipt_spec is None or receipt_spec.loader is None:
        raise RuntimeError("Cannot load completed-build receipt helper")
    receipt = importlib.util.module_from_spec(receipt_spec)
    receipt_spec.loader.exec_module(receipt)
    # A prior successful build is no longer evidence once outputs may change.
    receipt.invalidate_receipt(app)
    env = os.environ.copy()
    env["PATH"] = str(src / "third_party/llvm-build/Release+Asserts/bin") + os.pathsep + env["PATH"]
    # Match the system esbuild binary required by the pinned upstream patches.
    # --ignore-scripts prevents npm lifecycle execution. This dependency is
    # chosen by the installed Homebrew tool, so binary reproducibility is not claimed.
    version = output("/opt/homebrew/bin/esbuild", "--version")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise RuntimeError("Unexpected esbuild version")
    module = recipe / "build/esbuild-node/node_modules/esbuild"
    package = module / "package.json"
    if not package.is_file() or json.loads(package.read_text())["version"] != version:
        run("npm", "install", "--prefix", recipe / "build/esbuild-node", "--no-save", "--package-lock=false", "--no-bin-links", "--ignore-scripts", "--omit=optional", "--no-audit", "--no-fund", f"esbuild@{version}")
    link = src / "third_party/devtools-frontend/src/node_modules/esbuild"
    if link.is_symlink() or link.is_file():
        link.unlink()
    elif link.is_dir():
        shutil.rmtree(link)
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(module)
    gn = src / "out/Default/gn"
    if not gn.is_file():
        run(sys.executable, src / "tools/gn/bootstrap/bootstrap.py", "-o", gn, "--skip-generate-buildfiles", cwd=src, env=env)
    if not (src / "third_party/rust-toolchain/bin/bindgen").is_file():
        run(sys.executable, src / "tools/rust/build_bindgen.py", "--skip-test", cwd=src,
            env=bindgen_environment(src, env))
    run(gn, "gen", "out/Default", "--fail-on-unused-args", cwd=src, env=env)
    if digest(args_path) != built_args:
        raise RuntimeError("Locked GN arguments changed during generation; no browser compilation started")
    run("ninja", "-C", "out/Default", "-j", jobs, "chrome", cwd=src, env=env)
    # Use upstream's explicit helper/framework entitlements and signing order.
    # This creates a locally ad-hoc signed engine DMG; no credentials or upload.
    env.update(MACOS_AD_HOC_SIGNING="1", CHROMIUM_SRC_DIR=str(src))
    run("bash", recipe / "sign_and_package_app.sh", work / "chromium-source-arm64.dmg", env=env)
    if not app.is_dir():
        raise RuntimeError(f"Build completed without expected engine bundle: {app}")
    if input_digest() != build_inputs or digest(args_path) != built_args:
        raise RuntimeError("Source inputs or GN arguments changed during compilation; no completed-build receipt recorded")
    compatibility_linker(src, lock, verify_only=True)
    run(sys.executable, ROOT / "scripts/malware_overlay.py", src, "--verify-applied")
    receipt.record_build(app, ROOT, build_inputs, args_path)
    print(f"Compiled and locally signed engine: {app}")
    return app


def self_test():
    with tempfile.TemporaryDirectory(prefix="kumo-source-test-") as folder:
        root = Path(folder)
        branding = root / "chrome/app/theme/chromium/BRANDING"
        branding.parent.mkdir(parents=True)
        branding.write_text("PRODUCT_FULLNAME=Chromium\nPRODUCT_SHORTNAME=Chromium\nPRODUCT_INSTALLER_FULLNAME=Chromium Installer\nPRODUCT_INSTALLER_SHORTNAME=Chromium Installer\nMAC_BUNDLE_ID=org.chromium.Chromium\nCOPYRIGHT=preserve me\n")
        strings = root / "chrome/app/chromium_strings.grd"
        strings.write_text("\n".join(f'<message name="{name}">Chromium</message>' for name in ("IDS_PRODUCT_NAME", "IDS_SHORT_PRODUCT_NAME", "IDS_ACCNAME_APP", "IDS_FIRST_RUN_DIALOG_WINDOW_TITLE", "IDS_TASK_MANAGER_TITLE")))
        features = root / "content/public/common/content_features.cc"
        features.parent.mkdir(parents=True)
        features.write_text("BASE_FEATURE(kFedCm, base::FEATURE_DISABLED_BY_DEFAULT);\n")
        extensions = root / "chrome/browser/extensions/chrome_content_browser_client_extensions_part.cc"
        extensions.parent.mkdir(parents=True)
        extensions.write_text("GetOriginsRequiringDedicatedProcess() {\n  std::vector<url::Origin> list;\n  return list;\n}\n")
        brand_source(root)
        assert "PRODUCT_FULLNAME=Chromium\n" in branding.read_text()
        assert "MAC_BUNDLE_ID=app.kumo.browser.engine" in branding.read_text()
        assert "COPYRIGHT=preserve me" in branding.read_text()
        assert "Chromium" not in strings.read_text()
        assert "FEATURE_ENABLED_BY_DEFAULT" in features.read_text()
        assert 'GURL("https://chromewebstore.google.com")' in extensions.read_text()
        assert merge_gn('x=1\ny=false\n', 'x=2\n').count('x = ') == 1
        assert "x = 2" in merge_gn('x=1\n', 'x=2\n')
        verify_file(branding, digest(branding))
        try:
            verify_file(branding, "0" * 64)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Checksum mismatch was accepted")
        try:
            brand_source(root)  # Refuse to apply the website feature overlay twice.
        except RuntimeError:
            pass
        else:
            raise AssertionError("Repeated source overlay was accepted")
    print("Offline source fixtures passed: branding, FedCM, copyright/name preservation, GN override, checksum rejection, Store origin isolation, non-repeatable overlay guard.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("doctor", "prepare", "build", "package", "self-test"))
    parser.add_argument("--work-dir", type=Path, default=ROOT / "build/source")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--dry-run", action="store_true", help="Print the pipeline without downloads, writes or compilation")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    if args.command == "self-test":
        self_test()
        return
    lock = lock_data()
    work = args.work_dir.resolve()
    if " " in str(work):
        parser.error("Chromium source/build paths must not contain spaces")
    if args.dry_run:
        print(f"Pinned Chromium {lock['chromiumVersion']} / mac packaging {lock['macosPackaging']['commit']}\nWorkspace: {work}")
        print("prepare: verify pinned checkouts; copy isolated recipe; download+verify locked archive; prune; apply both patch stacks; domain substitution; download+verify arm64 tools and immutable SDK-compatible linker; brand Kumo; restore Store isolation + FedCM; add native Passwords, anonymous signed Store updates, and malware download completion gate; write GN args")
        print(f"build: GN bootstrap; Rust bindgen; gn gen --fail-on-unused-args; ninja -C out/Default -j {args.jobs} chrome; upstream ad-hoc signing")
        print(f"package: python3 scripts/package.py --engine-app {work / 'recipe/build/src' / lock['engineBundle']}")
        print("No commands executed. Safe Browsing is unavailable in this source base; native Apple Passwords source integration requires compilation and runtime validation.")
        return
    if args.command == "doctor":
        doctor(lock)
    elif args.command == "prepare":
        doctor(lock)
        prepare(work, lock)
    else:
        app = build(work, lock, args.jobs)
        if args.command == "package":
            run(sys.executable, ROOT / "scripts/package.py", "--engine-app", app)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Kumo source build: {error}", file=sys.stderr)
        sys.exit(1)
