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
    age = (datetime.datetime.now(datetime.timezone.utc) - released).days
    if age > FEED_MAX_AGE_DAYS or SENTINEL not in kev or len(kev) < 500:
        print(f"KEV gate: feed not trusted (age {age}d, {len(kev)} entries, sentinel {SENTINEL in kev}); failing closed", file=sys.stderr)
        return 2
    results = scan.get("Results") if isinstance(scan, dict) else None
    sid = ((scan.get("Metadata") or {}).get("ImageID") if isinstance(scan, dict) else None)
    if not isinstance(results, list) or not results:
        print("KEV gate: scan has no Results; failing closed", file=sys.stderr)
        return 2
    if sid != a.image_id:
        print(f"KEV gate: scan ImageID {sid} is not the built image {a.image_id}; failing closed", file=sys.stderr)
        return 2
    classes = {r.get("Class") for r in results}
    lacking = [c for c in a.require_class if not any(r.get("Class") == c and r.get("Packages") for r in results)]
    if lacking:
        print(f"KEV gate: no scanned packages of class {lacking} (classes seen {sorted(map(str, classes))}); failing closed", file=sys.stderr)
        return 2
    pkgs = {p.get("Name") for r in results for p in (r.get("Packages") or [])}
    missing = [p for p in a.require_pkg if p not in pkgs]
    if missing:
        print(f"KEV gate: required packages not in the scan {missing} ({len(pkgs)} packages seen); failing closed", file=sys.stderr)
        return 2
    allow = load_allow(a.allow)
    hits, allowed = set(), set()
    for res in results:
        for v in res.get("Vulnerabilities") or []:
            if v.get("VulnerabilityID") in kev:
                key = (v["VulnerabilityID"], v.get("PkgName", "?"))
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
