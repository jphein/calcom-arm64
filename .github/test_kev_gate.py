#!/usr/bin/env python3
"""Fixture tests for kev_gate.py (no network). Run: python3 .github/test_kev_gate.py"""
import datetime, json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "kev_gate.py")
NOW = datetime.datetime.now(datetime.timezone.utc).isoformat()


def feed(released=NOW, drop=(), count_off=0):
    ids = ["CVE-2025-55182", "CVE-2025-31125"] + [f"CVE-2000-{i}" for i in range(1600)]
    v = [{"cveID": c} for c in ids if c not in drop]
    return {"dateReleased": released, "count": len(v) + count_off, "vulnerabilities": v}


def scan(vulns, pkgs=("next", "vite"), image="sha256:abc", results=True, os_result=True, versions=None, vendor=None):
    if not results:
        return {"Metadata": {"ImageID": image}, "Results": []}
    v = [{"VulnerabilityID": c, "PkgName": p, "InstalledVersion": "x", "VendorIDs": vendor or []} for c, p in vulns]
    res = [{"Target": "node", "Class": "lang-pkgs", "Packages": [{"Name": p, "Version": (versions or {}).get(p, "1.0.0")} for p in pkgs], "Vulnerabilities": v}]
    if os_result:
        res.append({"Target": "debian", "Class": "os-pkgs", "Packages": [{"Name": "libc6"}]})
    return {"Metadata": {"ImageID": image}, "Results": res}


CASES = [  # name, scan, feed, allow, args, want
    ("KEV next blocks", scan([("CVE-2025-55182", "next")]), feed(), "", ["--require-pkg", "next"], 1),
    ("allowed vite passes", scan([("CVE-2025-31125", "vite")]), feed(), "CVE-2025-31125 vite exp:2099-01-01\n", ["--require-pkg", "next"], 0),
    ("allow is per package", scan([("CVE-2025-31125", "esbuild")]), feed(), "CVE-2025-31125 vite exp:2099-01-01\n", [], 1),
    ("expired allow blocks", scan([("CVE-2025-31125", "vite")]), feed(), "CVE-2025-31125 vite exp:2000-01-01\n", [], 1),
    ("empty results fail closed", scan([], results=False), feed(), "", [], 2),
    ("wrong image fails closed", scan([], image="sha256:zzz"), feed(), "", [], 2),
    ("missing required pkg fails closed", scan([], pkgs=("vite",)), feed(), "", ["--require-pkg", "next"], 2),
    ("stale feed fails closed", scan([]), feed(released="2025-01-01T00:00:00Z"), "", [], 2),
    ("feed without sentinel fails closed", scan([]), feed(drop=("CVE-2025-55182",)), "", [], 2),
    ("partial scan (no os-pkgs) fails closed", scan([], os_result=False), feed(), "", ["--require-pkg", "next", "--require-class", "os-pkgs", "--require-class", "lang-pkgs"], 2),
    ("full-coverage clean scan passes", scan([]), feed(), "", ["--require-pkg", "next", "--require-class", "os-pkgs", "--require-class", "lang-pkgs"], 0),
    ("KEV under a GHSA id with the CVE as a vendor alias blocks", scan([("GHSA-9qr9-h5gf-34mp", "next")], vendor=["CVE-2025-55182"]), feed(), "", [], 1),
    ("an allowed alias does not hide an unallowed KEV id", scan([("CVE-2025-55182", "vite")], vendor=["CVE-2025-31125"]), feed(),
     "CVE-2025-31125 vite exp:2099-01-01\n", [], 1),
    ("a scan with no packages fails closed", {"Metadata": {"ImageID": "sha256:abc"}, "Results": [{}]}, feed(), "", [], 2),
    ("a future-dated feed fails closed", scan([]), feed(released="2099-01-01T00:00:00Z"), "", [], 2),
    ("a garbage installed version is below the floor", scan([], versions={"next": "15.5.7garbage"}), feed(), "",
     ["--require-min", "next=15.5.7"], 1),
    ("a garbage floor fails closed", scan([]), feed(), "", ["--require-min", "next=garbage"], 2),
    ("a feed an hour in the future fails closed", scan([]),
     feed(released=(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat()), "", [], 2),
    ("a required minimum for an absent package fails closed", scan([], pkgs=("vite",)), feed(), "", ["--require-min", "next=15.5.7"], 2),
    ("a pre-release floor fails closed", scan([]), feed(), "", ["--require-min", "next=15.5.7-canary.2"], 2),
    ("nameless package entries are no coverage", {"Metadata": {"ImageID": "sha256:abc"}, "Results": [{"Packages": [{}]}]}, feed(), "", [], 2),
    ("a feed whose count disagrees fails closed", scan([]), feed(count_off=1), "", [], 2),
    ("a feed of 600 entries is too short", scan([]),
     {"dateReleased": NOW, "count": 602, "vulnerabilities": [{"cveID": c} for c in ["CVE-2025-55182", "CVE-2025-31125"] + [f"CVE-2000-{i}" for i in range(600)]]},
     "", [], 2),
    ("next below the floor blocks", scan([], versions={"next": "15.5.4"}), feed(), "", ["--require-min", "next=15.5.7"], 1),
    ("next pre-release below the floor blocks", scan([], versions={"next": "15.5.7-canary.1"}), feed(), "", ["--require-min", "next=15.5.7"], 1),
    ("next at the floor passes", scan([], versions={"next": "15.5.7"}), feed(), "", ["--require-min", "next=15.5.7"], 0),
    ("next 16 passes a 15.5.7 floor", scan([], versions={"next": "16.1.5"}), feed(), "", ["--require-min", "next=15.5.7"], 0),
    ("clean scan passes", scan([]), feed(), "", ["--require-pkg", "next"], 0),
]


def main():
    bad = 0
    with tempfile.TemporaryDirectory() as d:
        for name, s, f, allow, args, want in CASES:
            for fn, obj in (("s.json", s), ("k.json", f)):
                json.dump(obj, open(os.path.join(d, fn), "w"))
            open(os.path.join(d, "a.txt"), "w").write(allow)
            rc = subprocess.run([sys.executable, GATE, *(os.path.join(d, x) for x in ("s.json", "k.json", "a.txt")),
                                 "--image-id", "sha256:abc", *args], capture_output=True).returncode
            ok = rc == want
            bad += not ok
            print(("ok  " if ok else "FAIL"), name, f"rc={rc} want={want}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
