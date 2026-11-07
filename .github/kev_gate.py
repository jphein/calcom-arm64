#!/usr/bin/env python3
"""KEV gate: fail when a trivy image scan holds a CISA Known-Exploited CVE that kev-allow.txt does not cover.

kev-allow.txt lines: `<CVE> <pkg> exp:YYYY-MM-DD # reason`. An expired line no longer allows; a CVE allowed
for one package still fails for another. Exit 0 clean, 1 KEV found, 2 bad input (an unreadable scan or KEV feed
must fail the build, never pass it).

Coverage: an empty or partial scan must not pass. --image-id must equal the scan's Metadata.ImageID, and every
--require-pkg must appear among the scanned packages (trivy --list-all-pkgs), so "nothing was scanned" cannot
read as "clean". The KEV feed must be fresh (dateReleased within FEED_MAX_AGE_DAYS) and hold SENTINEL.
"""
import argparse, datetime, json, re, sys

FEED_MAX_AGE_DAYS = 14
SENTINEL = "CVE-2025-55182"  # the incident CVE: a feed without it is not the feed we think it is


_VER = re.compile(r"v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")


def _ver(v):
    """Numeric release tuple ('15.5.7' -> (15, 5, 7, 0)); a pre-release sorts below its release. The WHOLE
    string must parse: anything else returns None, and callers fail closed on it."""
    m = _VER.fullmatch(str(v or ""))
    if not m:
        return None
    return tuple(int(x) for x in m[1].split(".")) + ((-1,) if m[2] else (0,))


def load_allow(path):
    allow, today = {}, datetime.date.today()
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        return allow
    for n, line in enumerate(lines, 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"(CVE-\d{4}-\d+)\s+(\S+)\s+exp:(\d{4}-\d{2}-\d{2})", line)
        if not m:
            sys.exit(f"kev-allow.txt:{n}: want '<CVE> <pkg> exp:YYYY-MM-DD', got {line!r}")
        if datetime.date.fromisoformat(m[3]) >= today:
            allow[(m[1], m[2])] = m[3]
        else:
            print(f"kev-allow.txt:{n}: {m[1]} {m[2]} expired {m[3]}, no longer allowed")
    return allow


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("scan"); ap.add_argument("kev"); ap.add_argument("allow")
    ap.add_argument("--image-id", required=True)
    ap.add_argument("--require-pkg", action="append", default=[])
    ap.add_argument("--require-min", action="append", default=[], help="pkg=version: every scanned copy of pkg must be >= version")
    ap.add_argument("--require-class", action="append", default=[], help="trivy result Class that must be present (os-pkgs, lang-pkgs)")
    a = ap.parse_args(argv)
    try:
        scan = json.load(open(a.scan))
        feed = json.load(open(a.kev))
        kev = {v["cveID"] for v in feed["vulnerabilities"]}
        released = datetime.datetime.fromisoformat(feed["dateReleased"].replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"KEV gate: unreadable input ({e!r}); failing closed", file=sys.stderr)
        return 2
    now = datetime.datetime.now(datetime.timezone.utc)
    age = (now - released).days
    future = released > now + datetime.timedelta(minutes=10)   # 10 min of clock skew; any later date is not fresh
    if age > FEED_MAX_AGE_DAYS or future or SENTINEL not in kev or len(kev) < 500:
        print(f"KEV gate: feed not trusted (age {age}d, future {future}, {len(kev)} entries, sentinel {SENTINEL in kev}); failing closed", file=sys.stderr)
        return 2
    results = scan.get("Results") if isinstance(scan, dict) else None
    sid = ((scan.get("Metadata") or {}).get("ImageID") if isinstance(scan, dict) else None)
    if not isinstance(results, list) or not results:
        print("KEV gate: scan has no Results; failing closed", file=sys.stderr)
        return 2
    if sid != a.image_id:
        print(f"KEV gate: scan ImageID {sid} is not the built image {a.image_id}; failing closed", file=sys.stderr)
        return 2
    named = lambda r: [p for p in (r.get("Packages") or []) if isinstance(p, dict) and isinstance(p.get("Name"), str) and p["Name"]]
    pkgs = {p["Name"] for r in results if isinstance(r, dict) for p in named(r)}
    if not pkgs:
        print("KEV gate: the scan lists no packages (run trivy with --list-all-pkgs); failing closed", file=sys.stderr)
        return 2
    classes = {r.get("Class") for r in results if isinstance(r, dict)}
    lacking = [c for c in a.require_class if not any(isinstance(r, dict) and r.get("Class") == c and named(r) for r in results)]
    if lacking:
        print(f"KEV gate: no scanned packages of class {lacking} (classes seen {sorted(map(str, classes))}); failing closed", file=sys.stderr)
        return 2
    missing = [p for p in a.require_pkg if p not in pkgs]
    if missing:
        print(f"KEV gate: required packages not in the scan {missing} ({len(pkgs)} packages seen); failing closed", file=sys.stderr)
        return 2
    for spec in a.require_min:
        name, _, floor = spec.partition("=")
        fv = _ver(floor)
        if not name or fv is None or fv[-1] == -1:   # a pre-release floor can't be compared safely: refused
            print(f"KEV gate: bad --require-min {spec!r}; failing closed", file=sys.stderr)
            return 2
        low = [p.get("Version") for r in results for p in (r.get("Packages") or [])
               if p.get("Name") == name and (_ver(p.get("Version")) is None or _ver(p.get("Version")) < fv)]
        if name not in pkgs:
            print(f"KEV gate: --require-min {name}: no such package in the scan; failing closed", file=sys.stderr)
            return 2
        if low:   # an unparsable installed version counts as below the floor
            print(f"KEV gate: {name} {sorted(set(map(str, low)))} below the required {floor}", file=sys.stderr)
            return 1
    allow = load_allow(a.allow)
    hits, allowed = set(), set()
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            ids = {v.get("VulnerabilityID")} | set(v.get("VendorIDs") or [])   # aliases: trivy may name a KEV by GHSA or a vendor CVE
            for kid in sorted(i for i in ids if i in kev):   # every KEV id on its own: an allowed alias hides nothing
                key = (kid, v.get("PkgName", "?"))
                row = (*key, v.get("InstalledVersion", "?"), v.get("FixedVersion") or "no fix", res.get("Target", "?"))
                (allowed if key in allow else hits).add(row)
    for r in sorted(allowed):
        print("allowed KEV:", *r)
    for r in sorted(hits):
        print("KEV:", *r)
    print(f"KEV gate: {len(hits)} blocking, {len(allowed)} allowed; {len(pkgs)} packages, feed {age}d old")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
