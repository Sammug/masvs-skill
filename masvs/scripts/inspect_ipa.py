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
    canary = any(s in symbols for s in CANARY)
    has_objc = any(s.startswith("_objc_") for s in symbols)
    has_swift = any(s.startswith(("_swift_", "__swift_", "_$s")) for s in symbols)
    notes = []
    arc = None
    if Path(name).name == "App" and not has_objc:
        kind = "dart-aot"
        notes.append("n/a: compiled Dart (AOT), no Objective-C")
    elif has_objc or has_swift or OBJC_SWIFT.search(text):
        kind = "objc-swift"
        arc = "_objc_release" in symbols or "_objc_autoreleaseReturnValue" in symbols
        if has_swift and not canary:
            notes.append("pure Swift: canary not emitted by compiler")
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


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout


def emit(payload: dict, code: int = 0) -> None:
    print(redact(json.dumps(payload, indent=2)))
    sys.exit(code)


def read_plist(plutil: str, path: Path) -> dict:
    try:
        data = json.loads(run([plutil, "-convert", "json", "-o", "-", str(path)]))
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def inspect_binary(otool: str, binary: Path, rel: str) -> dict:
    header = parse_otool_header(run([otool, "-hv", str(binary)]))
    imports = parse_otool_imports(run([otool, "-Iv", str(binary)]), rel)
    return {"path": rel, "pie": header["pie"], **imports}


def inspect_app(otool: str, plutil: str, work: Path) -> dict:
    apps = sorted((work / "Payload").glob("*.app"))
    if not apps:
        return {"error": "no Payload/*.app in ipa"}
    app = apps[0]
    info = read_plist(plutil, app / "Info.plist")
    exe = info.get("CFBundleExecutable") or app.stem
    binaries = []
    if (app / exe).is_file():
        binaries.append(inspect_binary(otool, app / exe, f"{app.name}/{exe}"))
    for fw in sorted((app / "Frameworks").glob("*.framework")):
        fw_exe = read_plist(plutil, fw / "Info.plist").get("CFBundleExecutable") or fw.stem
        if (fw / fw_exe).is_file():
            binaries.append(inspect_binary(otool, fw / fw_exe, f"Frameworks/{fw.name}/{fw_exe}"))
    return {"bundle_id": info.get("CFBundleIdentifier"), "ats": ats_from_info(info), "binaries": binaries}


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        emit({"error": "usage: inspect_ipa.py <ipa>"}, 2)
    ipa = Path(argv[1])
    if not ipa.is_file():
        emit({"error": f"not a file: {ipa.name}"}, 2)
    otool, plutil, unzip = (shutil.which(t) for t in ("otool", "plutil", "unzip"))
    if sys.platform != "darwin" or not (otool and plutil and unzip):
        emit({"skipped": "otool, plutil and unzip are required (macOS with Xcode command line tools)"})
    with tempfile.TemporaryDirectory() as tmp:
        r = subprocess.run([unzip, "-q", "-o", str(ipa), "-d", tmp], capture_output=True, text=True)
        if r.returncode not in (0, 1):
            emit({"error": "could not unzip ipa"}, 2)
        result = inspect_app(otool, plutil, Path(tmp))
    if "error" in result:
        emit(result, 2)
    emit(result)


if __name__ == "__main__":
    main(sys.argv)
