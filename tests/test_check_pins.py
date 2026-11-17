import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "masvs" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import check_pins  # noqa: E402

HAS_OPENSSL = shutil.which("openssl") is not None
needs_openssl = pytest.mark.skipif(not HAS_OPENSSL, reason="openssl not installed")

NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.invalid</domain>
    <pin-set{exp}>
{pins}
    </pin-set>
  </domain-config>
</network-security-config>
"""


def sh(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def make_chain(tmp_path):
    d = tmp_path
    ca_ext = d / "ca.ext"
    ca_ext.write_text("basicConstraints=critical,CA:TRUE\n")
    leaf_ext = d / "leaf.ext"
    leaf_ext.write_text("basicConstraints=CA:FALSE\nsubjectAltName=DNS:api.example.invalid\n")
    for name in ("root", "inter", "leaf"):
        sh("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{name}.key", cwd=d)
    sh("openssl", "req", "-new", "-x509", "-key", "root.key", "-subj", "/CN=Test Root", "-days", "30",
       "-addext", "basicConstraints=critical,CA:TRUE", "-out", "root.pem", cwd=d)
    for name, ext, signer in (("inter", "ca.ext", "root"), ("leaf", "leaf.ext", "inter")):
        sh("openssl", "req", "-new", "-key", f"{name}.key", "-subj", f"/CN=Test {name}", "-out", f"{name}.csr", cwd=d)
        sh("openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", f"{signer}.pem", "-CAkey", f"{signer}.key",
           "-CAcreateserial", "-days", "30", "-extfile", ext, "-out", f"{name}.pem", cwd=d)
    chain = d / "chain.pem"
    chain.write_text("".join((d / f"{n}.pem").read_text() for n in ("leaf", "inter", "root")))
    return chain, {n: check_pins.spki_b64((d / f"{n}.pem").read_text()) for n in ("leaf", "inter", "root")}


def write_nsc(tmp_path, pins, exp=None):
    body = "\n".join(f'      <pin digest="SHA-256">{p}</pin>' for p in pins)
    path = tmp_path / "nsc.xml"
    path.write_text(NSC.format(pins=body, exp=f' expiration="{exp}"' if exp else ""))
    return path


def run(args):
    r = subprocess.run([sys.executable, str(SCRIPTS / "check_pins.py"), *map(str, args)],
                       capture_output=True, text=True)
    return r


@needs_openssl
def test_intermediate_pin_detected(tmp_path):
    chain, h = make_chain(tmp_path)
    nsc = write_nsc(tmp_path, [h["inter"]])
    r = run(["--nsc", nsc, "--chain", chain])
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)["domains"][0]
    assert d["pinned_level"] == "intermediate"
    assert d["live_match"] is True
    assert d["include_subdomains"] is True
    assert d["backup_pin"] is False
    assert d["matched_levels"] == ["intermediate"]


@needs_openssl
def test_leaf_pin_warns(tmp_path):
    chain, h = make_chain(tmp_path)
    nsc = write_nsc(tmp_path, [h["leaf"], h["root"]])
    d = json.loads(run(["--nsc", nsc, "--chain", chain]).stdout)["domains"][0]
    assert d["pinned_level"] == "leaf"
    assert d["matched_levels"] == ["leaf", "root"]
    assert d["backup_pin"] is True


@needs_openssl
def test_root_and_no_match(tmp_path):
    chain, h = make_chain(tmp_path)
    d = json.loads(run(["--nsc", write_nsc(tmp_path, [h["root"]]), "--chain", chain]).stdout)["domains"][0]
    assert d["pinned_level"] == "root"
    d = json.loads(run(["--nsc", write_nsc(tmp_path, ["AAAA"]), "--chain", chain]).stdout)["domains"][0]
    assert d["live_match"] is False


def test_expiry_days_left(tmp_path):
    nsc = write_nsc(tmp_path, ["AAAA"], exp="2030-01-01")
    r = run(["--nsc", nsc, "--today", "2029-12-01"])
    d = json.loads(r.stdout)["domains"][0]
    assert d["days_left"] == 31
    assert d["expiration"] == "2030-01-01"
    assert d["pinned_level"] == "unknown"
    assert d["live_match"] is None


def test_no_expiration_and_no_pinset(tmp_path):
    p = tmp_path / "n.xml"
    p.write_text("""<network-security-config>
  <domain-config><domain>a.example.invalid</domain></domain-config>
  <domain-config>
    <domain>b.example.invalid</domain>
    <pin-set><pin digest="SHA-256">AAAA</pin></pin-set>
    <domain-config><domain>c.example.invalid</domain></domain-config>
  </domain-config>
</network-security-config>""")
    doms = {d["domain"]: d for d in json.loads(run(["--nsc", p]).stdout)["domains"]}
    assert doms["a.example.invalid"]["pinned_level"] == "none"
    assert doms["a.example.invalid"]["pins"] == []
    assert doms["b.example.invalid"]["days_left"] is None
    assert doms["c.example.invalid"]["pins"] == ["AAAA"]


def test_bad_inputs_exit_2(tmp_path):
    r = run(["--nsc", tmp_path / "missing.xml"])
    assert r.returncode == 2 and "error" in json.loads(r.stdout)
    bad = tmp_path / "bad.xml"
    bad.write_text("<not-closed")
    r = run(["--nsc", bad])
    assert r.returncode == 2 and "error" in json.loads(r.stdout)


def test_no_openssl_skips(tmp_path):
    nsc = write_nsc(tmp_path, ["AAAA"])
    chain = tmp_path / "chain.pem"
    chain.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    r = subprocess.run([sys.executable, str(SCRIPTS / "check_pins.py"), "--nsc", str(nsc), "--chain", str(chain)],
                       capture_output=True, text=True, env={"PATH": ""})
    assert r.returncode == 0
    assert "skipped" in json.loads(r.stdout)
