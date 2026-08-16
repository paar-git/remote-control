Connect-and-accept rewrite. One program is both sides: it shows this machine’s address and it dials another. Completing TLS still admits nothing — a pin, an unattended password, or a person clicking Accept decides.

## Installers

- Windows: `Remote.Control_0.2.0_x64_en-US.msi`
- macOS Apple Silicon: `Remote.Control_0.2.0_aarch64.dmg`
- macOS Intel: `Remote.Control_0.2.0_x64.dmg`
- Linux: `Remote.Control_0.2.0_amd64.deb` and `.AppImage`

There is still no remote display. A session can transfer files and show live metrics. Screen capture and input injection are not in this version.

## Features

- The main window, the accept dialog, the session and settings
- Embed the host side in the desktop application
- Carry the accept decision over the wire
- Shrink monitoring to a session strip
- Replace trust, owner and audit with recent and settings
- Parse the address a user types
- Reduce the permission model to four permissions (control, files, metrics, administer)

## Fixes

- Stop disclosing the machine before the accept decision
- Coarsen wire refusals, close lockout race, gate one dialog, equalize over-long password timing, centralize empty-grant refusal
- Correlate the accept answer with its request
- Retry an address that could not be resolved
- Delete the owner-account gate and its unbacked commands

Breaking: pairing, the owner account, mDNS, the coordination server, the privileged helper and the remote terminal are gone. An existing database loses trusted devices, the owner account and the audit trail.
