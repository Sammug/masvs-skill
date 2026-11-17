import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import redact  # noqa: E402

COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")


def _version_key(p: Path) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", p.parent.name))


def find_sdk_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    roots = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             str(Path.home() / "Library" / "Android" / "sdk")]
    pattern = f"build-tools/*/{name}" if name == "aapt2" else f"cmdline-tools/*/bin/{name}"
    for root in roots:
        if not root:
            continue
        hits = sorted(Path(root).glob(pattern), key=_version_key)
        if name != "aapt2":
            hits += sorted(Path(root).glob(f"tools/bin/{name}"))
        if hits:
            return str(hits[-1])
    return None


def parse_badging(text: str) -> dict:
    out: dict = {"min_sdk": None, "target_sdk": None, "permissions": []}
    for line in text.splitlines():
        m = re.match(r"(minSdkVersion|targetSdkVersion):'(\d+)'", line)
        if m:
            out["min_sdk" if m.group(1) == "minSdkVersion" else "target_sdk"] = int(m.group(2))
            continue
        m = re.match(r"uses-permission(?:-sdk-\d+)?: name='([^']+)'", line)
        if m and m.group(1) not in out["permissions"]:
            out["permissions"].append(m.group(1))
    return out


_A_RE = re.compile(r"A: ([^=]+?)=(.*)$")
_STR_RE = re.compile(r'^"(.*)"(?: \(Raw: ".*"\))?$')


def _xmltree_value(raw: str):
    raw = raw.strip()
    m = _STR_RE.match(raw)
    if m:
        return m.group(1)
    if raw in ("true", "false"):
        return raw == "true"
    if raw in ("0xffffffff", "-1"):
        return True
    if raw == "0x0":
        return False
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    return raw


def _tree_from_xmltree(text: str) -> dict:
    root = {"tag": "#root", "attrs": {}, "children": []}
    stack = [(-1, root)]
    for line in text.splitlines():
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if stripped.startswith("E: "):
            node = {"tag": stripped[3:].split(" ")[0], "attrs": {}, "children": []}
            while stack[-1][0] >= indent:
                stack.pop()
            stack[-1][1]["children"].append(node)
            stack.append((indent, node))
        elif stripped.startswith("A: "):
            m = _A_RE.match(stripped)
            if m and len(stack) > 1:
                key = re.sub(r"\(0x[0-9a-fA-F]+\)$", "", m.group(1)).rsplit(":", 1)[-1]
                stack[-1][1]["attrs"][key] = _xmltree_value(m.group(2))
    return root


def _bool_attr(value):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    return None


def _tree_from_et(el: ET.Element) -> dict:
    attrs = {k.rsplit("}", 1)[-1]: v for k, v in el.attrib.items()}
    for k, v in list(attrs.items()):
        if v in ("true", "false"):
            attrs[k] = v == "true"
        elif re.fullmatch(r"-?\d+", v):
            attrs[k] = int(v)
    return {"tag": el.tag, "attrs": attrs, "children": [_tree_from_et(c) for c in el]}


def parse_manifest_xml(text: str) -> dict:
    return _analyse({"tag": "#root", "attrs": {}, "children": [_tree_from_et(ET.fromstring(text))]})


def parse_xmltree(text: str) -> dict:
    return _analyse(_tree_from_xmltree(text))


def _find(node: dict, tag: str) -> list[dict]:
    return [c for c in node["children"] if c["tag"] == tag]


def _analyse(root: dict) -> dict:
    manifests = _find(root, "manifest")
    manifest = manifests[0] if manifests else {"attrs": {}, "children": []}
    sdk = (_find(manifest, "uses-sdk") or [{"attrs": {}}])[0]["attrs"]
    min_sdk, target_sdk = sdk.get("minSdkVersion"), sdk.get("targetSdkVersion")
    perms: list[str] = []
    for p in _find(manifest, "uses-permission"):
        n = p["attrs"].get("name")
        if isinstance(n, str) and n not in perms:
            perms.append(n)
    app = (_find(manifest, "application") or [{"attrs": {}, "children": []}])[0]
    attrs = app["attrs"]
    nsc = attrs.get("networkSecurityConfig")
    exported = []
    for comp in app["children"]:
        if comp["tag"] not in COMPONENTS:
            continue
        flag = _bool_attr(comp["attrs"].get("exported"))
        if flag is None and isinstance(target_sdk, int) and target_sdk < 31:
            flag = bool(_find(comp, "intent-filter"))
        if flag:
            perm = comp["attrs"].get("permission")
            exported.append({"name": comp["attrs"].get("name"), "permission": perm if isinstance(perm, str) else None})
    return {
        "min_sdk": min_sdk if isinstance(min_sdk, int) else None,
        "target_sdk": target_sdk if isinstance(target_sdk, int) else None,
        "allow_backup": _bool_attr(attrs.get("allowBackup")),
        "uses_cleartext": _bool_attr(attrs.get("usesCleartextTraffic")),
        "network_security_config": nsc if isinstance(nsc, str) else None,
        "exported": exported,
        "permissions": perms,
        "debuggable": _bool_attr(attrs.get("debuggable")) is True,
    }


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout


def emit(payload: dict, code: int = 0) -> None:
    print(redact(json.dumps(payload, indent=2)))
    sys.exit(code)


def main(argv: list[str]) -> None:
    if len(argv) != 2:
        emit({"error": "usage: inspect_apk.py <apk>"}, 2)
    apk = Path(argv[1])
    if not apk.is_file():
        emit({"error": f"not a file: {apk.name}"}, 2)
    aapt2 = find_sdk_tool("aapt2")
    if aapt2:
        manifest = parse_xmltree(run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)]))
        badging = parse_badging(run([aapt2, "dump", "badging", str(apk)]))
    else:
        analyzer = find_sdk_tool("apkanalyzer")
        if not analyzer:
            emit({"skipped": "neither aapt2 nor apkanalyzer found (install Android SDK build-tools or set ANDROID_HOME)"})
        try:
            manifest = parse_manifest_xml(run([analyzer, "manifest", "print", str(apk)]))
        except ET.ParseError:
            emit({"skipped": "apkanalyzer produced no readable manifest"})
        badging = {"min_sdk": None, "target_sdk": None, "permissions": []}
    if not manifest["permissions"]:
        manifest["permissions"] = badging["permissions"]
    for key in ("min_sdk", "target_sdk"):
        if manifest[key] is None:
            manifest[key] = badging[key]
    emit(manifest)


if __name__ == "__main__":
    main(sys.argv)
