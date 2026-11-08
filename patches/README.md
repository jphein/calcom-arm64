# Source patches (fork-first)

Applied to the cal.com checkout by the build workflow before the Docker build (`git apply`, in file order). Each patch
is a fix we needed before upstream had it; every one is also opened upstream at calcom/cal.com and dropped here once a
release carries it. The image tag gets a `-p<N>` suffix (N = patches applied) so a patched build never overwrites an
unpatched tag.

| patch | why | upstream |
|---|---|---|
| 0001-googlecalendar-retry-post-insert-patch | Google throttles the description PATCH Cal.com sends right after `events.insert` (403 usageLimits/rateLimitExceeded, measured 2026-11-07: 3 of 6 immediate patches fail, a retry 1 s later passes). Cal.com treated the whole createEvent as failed and stored no event id, so cancels/reschedules never reached Google. Retry with 1/2/4 s backoff; on final failure keep the created event. | PR to calcom/cal.com (pending) |
| 0002-next-15.5.28-image-optimizer-rce | cal.com v5.9.10 pins next 15.5.7, which has two unauthenticated RCEs in the Image Optimization API (GHSA-2xp9-vwfh-vxw4 AVIF, fixed 15.5.24; GHSA-2464-fhr4-w9xw SVG, fixed 15.5.28) plus the Windows-only CVE-2026-75604 and DoS/cache advisories. A root `resolutions` entry forces every `next` in the pruned workspace to 15.5.28 (0 advisories list it as affected, checked 2026-11-08 with 15.5.7 as the positive control); the KEV gate's `--require-min next=15.5.28` proves the shipped image carries it. Drop when a cal.com release pins next >= 15.5.28. | none needed (upstream bumps next in its own releases) |
