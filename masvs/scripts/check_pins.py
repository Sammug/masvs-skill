import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import redact  # noqa: E402

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
LEVEL_ORDER = ["leaf", "intermediate", "root"]


class ToolError(Exception):
    pass


def emit(obj: dict, code: int = 0) -> None:
    print(json.dumps(obj, indent=2))
    sys.exit(code)


def openssl(args: list[str], stdin: str = "", timeout: int = 15, binary: bool = False):
    try:
        r = subprocess.run(["openssl", *args], input=stdin.encode(), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError("openssl timed out") from None
    except OSError as e:
        raise ToolError(f"openssl failed: {e.strerror}") from None
    if r.returncode != 0 and not (args and args[0] == "s_client" and r.stdout):
        raise ToolError("openssl failed: " + redact(r.stderr.decode(errors="replace").strip()[:200]))
    return r.stdout if binary else r.stdout.decode(errors="replace")


def spki_b64(pem: str) -> str:
    pub = openssl(["x509", "-pubkey", "-noout"], pem, binary=True)
    der = openssl(["pkey", "-pubin", "-outform", "der"], pub.decode(), binary=True)
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def self_signed(pem: str) -> bool:
    out = openssl(["x509", "-noout", "-subject", "-issuer"], pem)
    vals = {}
    for line in out.splitlines():
        key, _, val = line.partition("=")
        vals[key.strip()] = val.strip()
    return bool(vals.get("subject")) and vals.get("subject") == vals.get("issuer")


def split_pems(text: str) -> list[str]:
    return [m.group(0) + "\n" for m in PEM_RE.finditer(text)]


def fetch_chain(host: str, port: int) -> list[str]:
    out = openssl(["s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"], "", timeout=15)
    return split_pems(out)


def parse_expiration(value: str | None, today: date) -> tuple[str | None, int | None]:
    if value is None:
        return None, None
    try:
        exp = date.fromisoformat(value.strip())
    except ValueError:
        raise ValueError(f"invalid expiration: {redact(value)[:40]}") from None
    return value.strip(), (exp - today).days


def collect(elem: ET.Element, inherited: dict | None, today: date, out: list[dict]) -> None:
    pin_set = elem.find("pin-set")
    if pin_set is not None:
        pins = [(p.text or "").strip() for p in pin_set.findall("pin") if p.get("digest", "").upper() == "SHA-256"]
        exp, days = parse_expiration(pin_set.get("expiration"), today)
        info = {"pins": pins, "expiration": exp, "days_left": days}
    else:
        info = inherited or {"pins": [], "expiration": None, "days_left": None}
    for dom in elem.findall("domain"):
        name = (dom.text or "").strip()
        out.append({
            "domain": redact(name),
            "include_subdomains": dom.get("includeSubdomains", "false").lower() == "true",
            "pins": list(info["pins"]),
            "expiration": info["expiration"],
            "days_left": info["days_left"],
            "backup_pin": len(info["pins"]) >= 2,
            "pinned_level": "none" if not info["pins"] else "unknown",
            "matched_levels": [],
            "live_match": None,
        })
    for child in elem.findall("domain-config"):
        collect(child, info if pin_set is not None or inherited else None, today, out)


def parse_nsc(path: Path, today: date) -> list[dict]:
    root = ET.parse(path).getroot()
    out: list[dict] = []
    for dc in root.findall("domain-config"):
        collect(dc, None, today, out)
    return out


def chain_levels(chain: list[str]) -> list[tuple[str, str]]:
    n = len(chain)
    result = []
    for i, pem in enumerate(chain):
        if i == 0:
            level = "leaf"
        elif i == n - 1 or self_signed(pem):
            level = "root"
        else:
            level = "intermediate"
        result.append((spki_b64(pem), level))
    return result


def apply_chain(entry: dict, levels: list[tuple[str, str]]) -> None:
    if not entry["pins"]:
        return
    pins = set(entry["pins"])
    matched = [lvl for h, lvl in levels if h in pins]
    entry["live_match"] = bool(matched)
    entry["matched_levels"] = [lv for lv in LEVEL_ORDER if lv in matched]
    entry["pinned_level"] = entry["matched_levels"][0] if matched else "unknown"


def main(argv: list[str]) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nsc", required=True)
    ap.add_argument("--host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--chain")
    ap.add_argument("--today")
    try:
        args = ap.parse_args(argv[1:])
    except SystemExit:
        emit({"error": "usage: check_pins.py --nsc FILE [--host H --port 443] [--chain PEM] [--today YYYY-MM-DD]"}, 2)
    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
    except ValueError:
        emit({"error": "invalid --today, expected YYYY-MM-DD"}, 2)
    nsc = Path(args.nsc)
    if not nsc.is_file():
        emit({"error": f"not a file: {redact(nsc.name)}"}, 2)
    try:
        domains = parse_nsc(nsc, today)
    except ET.ParseError:
        emit({"error": "invalid XML in network security config"}, 2)
    except ValueError as e:
        emit({"error": str(e)}, 2)

    chain_text = None
    if args.chain:
        chain_path = Path(args.chain)
        if not chain_path.is_file():
            emit({"error": f"not a file: {redact(chain_path.name)}"}, 2)
        chain_text = chain_path.read_text(errors="replace")
    if (chain_text is not None or args.host) and not shutil.which("openssl"):
        emit({"skipped": "openssl not found (install OpenSSL to compute SPKI hashes)"})
    try:
        if chain_text is not None:
            chain = split_pems(chain_text)
            if not chain:
                emit({"error": "no certificates found in chain file"}, 2)
            levels = chain_levels(chain)
            for d in domains:
                apply_chain(d, levels)
        elif args.host:
            levels = chain_levels(fetch_chain(args.host, args.port))
            if not levels:
                emit({"error": "no certificates returned by host"}, 2)
            for d in domains:
                if d["domain"] == args.host:
                    apply_chain(d, levels)
    except ToolError as e:
        emit({"error": str(e)}, 2)
    emit({"domains": domains})


if __name__ == "__main__":
    main(sys.argv)
