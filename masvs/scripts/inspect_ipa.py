from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import redact  # noqa: E402

CANARY = ("___stack_chk_guard", "___stack_chk_fail")
OBJC_SWIFT = re.compile(r"_objc_release|_objc_retain|_swift_|_\$s")


def parse_otool_imports(text: str, name: str = "") -> dict:
    symbols = set(re.findall(r"\s(_\S+)\s*$", text, re.M))
    canary: bool | None = any(s in symbols for s in CANARY)
    has_objc = any(s.startswith("_objc_") for s in symbols)
    has_swift = any(s.startswith(("_swift_", "__swift_", "_$s")) for s in symbols)
    has_rr = "_objc_release" in symbols or "_objc_retain" in symbols
    notes = []
    arc = None
    if Path(name).name == "App" and not has_objc:
        kind = "dart-aot"
        canary = canary or None
        notes.append("n/a: compiled Dart (AOT), no Objective-C/C stack frames")
    elif has_objc or has_swift or OBJC_SWIFT.search(text):
        kind = "objc-swift"
        if has_swift and not has_rr:
            arc = None
            canary = canary or None
            if canary is None:
                notes.append("pure Swift: canary not emitted by compiler")
            notes.append("ARC is Swift's default (no Objective-C retain/release imports)")
        else:
            arc = "_objc_release" in symbols or "_objc_autoreleaseReturnValue" in symbols
    else:
        kind = "c"
    return {"stack_canary": canary, "arc": arc, "kind": kind, "note": "; ".join(notes) or None}


def parse_otool_header(text: str) -> dict:
    lines = text.splitlines()
    verdicts = []
    for i, line in enumerate(lines):
        if line.startswith("MH_MAGIC") or line.startswith("MH_CIGAM"):
            tokens = line.split()
            filetype = tokens[4] if len(tokens) > 4 else ""
            verdicts.append("PIE" in tokens or filetype in ("DYLIB", "BUNDLE"))
    return {"pie": all(verdicts) if verdicts else None}


def ats_from_info(info: dict) -> dict:
    ats = info.get("NSAppTransportSecurity")
    return ats if isinstance(ats, dict) else {}


class ToolError(Exception):
    pass


def run(cmd: list[str]) -> str:
    tool = Path(cmd[0]).name
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
    except subprocess.TimeoutExpired:
        raise ToolError(f"{tool} failed: timed out") from None
    except OSError as e:
        raise ToolError(f"{tool} failed: {e.strerror or e}") from None


def emit(payload: dict, code: int = 0) -> None:
    print(redact(json.dumps(payload, indent=2)))
    sys.exit(code)


def read_plist(plutil: str, path: Path) -> dict | None:
    try:
        data = json.loads(run([plutil, "-convert", "json", "-o", "-", str(path)]))
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def inspect_binary(otool: str, binary: Path, rel: str) -> dict:
    header = parse_otool_header(run([otool, "-hv", str(binary)]))
    imports = parse_otool_imports(run([otool, "-Iv", str(binary)]), rel)
    return {"path": rel, "pie": header["pie"], **imports}


def inspect_bundle(otool: str, plutil: str, bundle: Path, rel: str, notes: list[str]) -> tuple[dict, list[dict]]:
    info = read_plist(plutil, bundle / "Info.plist")
    if info is None:
        notes.append(f"{rel}: Info.plist unreadable, ATS not assessed")
    exe = (info or {}).get("CFBundleExecutable") or bundle.stem
    binaries = []
    if (bundle / exe).is_file():
        binaries.append(inspect_binary(otool, bundle / exe, f"{rel}/{exe}"))
    entry = {
        "path": rel,
        "bundle_id": (info or {}).get("CFBundleIdentifier"),
        "ats": ats_from_info(info) if info is not None else None,
    }
    return entry, binaries


def inspect_app(otool: str, plutil: str, work: Path) -> dict:
    apps = sorted((work / "Payload").glob("*.app"))
    if not apps:
        return {"error": "no Payload/*.app in ipa"}
    app = apps[0]
    notes: list[str] = []
    main_entry, binaries = inspect_bundle(otool, plutil, app, app.name, notes)
    bundles = [main_entry]
    for fw in sorted((app / "Frameworks").glob("*.framework")):
        fw_info = read_plist(plutil, fw / "Info.plist") or {}
        fw_exe = fw_info.get("CFBundleExecutable") or fw.stem
        if (fw / fw_exe).is_file():
            binaries.append(inspect_binary(otool, fw / fw_exe, f"Frameworks/{fw.name}/{fw_exe}"))
    for appex in sorted((app / "PlugIns").glob("*.appex")):
        entry, appex_bins = inspect_bundle(otool, plutil, appex, f"PlugIns/{appex.name}", notes)
        bundles.append(entry)
        binaries += appex_bins
    return {
        "bundle_id": main_entry["bundle_id"],
        "ats": main_entry["ats"],
        "bundles": bundles,
        "binaries": binaries,
        "notes": notes,
    }


def main(argv: list[str]) -> None:
    if len(argv) == 2 and argv[1] in ("-h", "--help"):
        print("usage: inspect_ipa.py <ipa>")
        sys.exit(0)
    if len(argv) != 2:
        emit({"error": "usage: inspect_ipa.py <ipa>"}, 2)
    ipa = Path(argv[1])
    if not ipa.is_file():
        emit({"error": f"not a file: {ipa.name}"}, 2)
    otool, plutil, unzip = (shutil.which(t) for t in ("otool", "plutil", "unzip"))
    if sys.platform != "darwin" or not (otool and plutil and unzip):
        emit({"skipped": "otool, plutil and unzip are required (macOS with Xcode command line tools)"})
    with tempfile.TemporaryDirectory() as tmp:
        try:
            r = subprocess.run([unzip, "-q", "-o", str(ipa), "-d", tmp], capture_output=True, text=True, timeout=300)
            if r.returncode not in (0, 1):
                emit({"error": "could not unzip ipa"}, 2)
            result = inspect_app(otool, plutil, Path(tmp))
        except (subprocess.TimeoutExpired, OSError):
            emit({"error": "unzip failed"}, 2)
        except ToolError as e:
            emit({"error": str(e)}, 2)
    if "error" in result:
        emit(result, 2)
    emit(result)


if __name__ == "__main__":
    main(sys.argv)
