# Pilot Delivery Security

This note is a technical packaging assessment for local AethelGard pilots. It is not
legal advice and does not create a customer license.

## Delivery Options

### A. Screen-share-only pilot

The owner runs AethelGard locally and shows the synthetic demo flow, redacted reports,
review queue, and support workflow in a call. No code, Git history, test fixtures,
internal agent files, reports, databases, or private project paths leave the owner
machine. This is the safest option for first feedback calls.

### B. Redacted demo pack

The owner shares only reviewed screenshots, demo HTML, and redacted sample reports.
There is no runtime artifact, so there is no customer-side execution. This is useful
for asynchronous review, but it cannot prove local installability.

### C. Python source package

A Python source package or dev-runtime folder is useful for internal dev tests only.
It is source-visible by design and must be clearly marked as not for customer delivery.
It must exclude `.git`, tests, reports, databases, internal agent files, and private
workspaces.

### D. PyInstaller build

PyInstaller can produce a local executable prototype when the dependency is already
available. It offers medium code protection, not a strong security boundary. The
binary still needs runtime smoke testing, legal/privacy review, and artifact scanning
before any pilot delivery.

### E. Nuitka build

Nuitka can offer better code protection than PyInstaller, but it usually has more
compiler and platform setup friction. Prepare it only as an owner-gated future build
path unless the toolchain is already present and the build is quick.

### F. Docker image

Docker is good for reproducible local execution and offline smoke testing. Docker
alone is not code protection if Python source files are copied into the image. A
closed customer delivery should prefer a reviewed binary or compiled runtime inside a
container, with the image scanned and distributed only after NDA/pilot-license review.

## Current Recommendation

For Pilot 1, use screen-share plus the synthetic demo report and landing page for first
conversations. For a real customer-side test, prepare a closed pilot artifact only
after NDA and pilot-license review.

Do not give GitHub access or a source ZIP to consultants or pilot customers. The
current `dev-runtime` artifact is a safety rehearsal: it proves packaging exclusions
and support instructions, but customers would see source code, so it is not
closed-source-ready.

## Required Gates Before Customer Delivery

- `python scripts/build_pilot_artifact.py --out dist/aethelgard-pilot --mode dev-runtime`
- `python scripts/check_delivery_artifact.py --path dist/aethelgard-pilot`
- Binary build proof if claiming `no_source_claim: true`.
- Docker runtime smoke only with owner approval and no push or registry upload.
- Legal/privacy review of the pilot notice, NDA, and contact details.
- Human review of every customer-facing report or support bundle.

The delivery checker stream-scans complete UTF-8 and UTF-16 text files with overlap
between chunks. A text-like file blocks delivery if its encoding is unsupported, it
cannot be read or decoded completely, or it exceeds 64 MiB. Recognized executables,
archives, media, and other binary formats identified from their content are not
interpreted as text; a binary-looking filename alone is not an exemption. Binary build
and runtime proof remain separate required gates.
