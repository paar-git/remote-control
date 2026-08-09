# Download, Installer and Update Manager

The desktop client uses shared Rust update primitives in `crates/updater`, Tauri commands in `apps/desktop-client/src-tauri/src/update_commands.rs`, and frontend state in `apps/desktop-client/src/UpdateScreen.tsx`. The same crate also exposes `rc-bootstrapper`, a small standalone entry point for fresh full-application installs.

## Trust Model

Remote metadata is never trusted until authenticated and validated.

- `release-index.json` lists compatible releases and is signed by `release-index.json.sig`.
- Each `release-manifest.json` is signed by `release-manifest.json.sig`.
- Manifest artifacts are verified with SHA-256 before installation.
- Platform package signatures are verified when the selected format requires and supports it: Authenticode on Windows, Apple signing/notarization checks where available on macOS, and native package signature tooling on Linux.
- Ed25519 metadata signing is separate from Windows Authenticode and Apple Developer ID signing. The repository contains only public verification keys.

Trusted verification keys live in `apps/desktop-client/src-tauri/release-public-keys.txt` and are embedded at compile time by `build.rs`, so a shipped build trusts the release channel with no runtime configuration. `RC_UPDATE_MANIFEST_PUBLIC_KEYS_B64` overrides the file when set at build time, which is how CI rotates keys. Both forms are a comma-separated keyring of 32-byte Ed25519 public keys, and shipping the current plus the next authorized key gives an overlap window for rotation. A manifest or index cannot authorize an arbitrary new key by itself.

Because a keyring is always embedded, the signature policy is `Required` in every build including debug ones; there is no unsigned-metadata path in a normal build. Private metadata signing keys, Windows code-signing certificates, Apple Developer ID certificates, and notarization credentials must be CI secrets and must never be committed.

## Update Discovery

A build with no saved configuration checks `https://github.com/<owner>/<repo>/releases/latest/download/release-index.json`, a stable endpoint that redirects to the newest published release. Precedence, most specific first: the URL passed to `check_for_updates`, the `RC_UPDATE_MANIFEST_URL` runtime environment variable, the URL saved in `update-config.json` from a previous check, then the compiled-in default (overridable at build time with `RC_UPDATE_METADATA_URL`).

The desktop client checks once on unlock and every six hours after that. The check is silent: failures are recorded but never raised to the user, because an offline machine must not greet its owner with an error. A background check is skipped entirely while a transfer or installation is running. When a newer version is found, a banner appears above the current section and a dot appears on the Updates sidebar item.

## Release Index

The updater can resolve the newest compatible version instead of blindly using the newest overall version. This prevents older operating systems from downloading an artifact that cannot run.

```json
{
  "schemaVersion": 1,
  "generatedAt": "2026-08-08T00:00:00.000Z",
  "releases": [
    {
      "version": "2.5.0",
      "releaseDate": "2026-08-08",
      "manifestUrl": "https://github.com/org/repo/releases/download/v2.5.0/release-manifest.json",
      "manifestSha256": "64 lowercase hex characters",
      "minimumOSVersion": { "windows": { "build": 22631 } },
      "platforms": { "windows-x64": { "formats": ["msi"] } }
    },
    {
      "version": "2.4.3",
      "releaseDate": "2026-08-07",
      "manifestUrl": "https://github.com/org/repo/releases/download/v2.4.3/release-manifest.json",
      "platforms": { "windows-x64": { "formats": ["msi"] } }
    }
  ]
}
```

The client verifies the signed index first, selects the newest compatible release, then verifies the selected signed manifest. If the index includes `manifestSha256`, the fetched manifest bytes must match that hash exactly.

## Release Manifest

A platform/architecture entry contains one or more artifacts. Unknown fields are rejected with `deny_unknown_fields` so compromised metadata cannot smuggle installer commands, paths, or unsupported behavior.

```json
{
  "version": "2.4.1",
  "releaseDate": "2026-08-07",
  "minimumSupportedVersion": "1.5.0",
  "minimumUpdaterVersion": "0.1.0",
  "minimumOSVersion": {
    "windows": { "build": 19045 },
    "macos": "13.0",
    "linux": { "kernel": "6.1", "glibc": "2.35" }
  },
  "mandatoryUpdate": false,
  "releaseNotes": "Improved performance and fixed crashes.",
  "platforms": {
    "windows-x64": {
      "artifacts": [
        {
          "format": "msi",
          "url": "https://downloads.example.com/remote-control-2.4.1-x64.msi",
          "sha256": "64 lowercase or uppercase hex characters",
          "size": 183921222,
          "installSize": 367842444,
          "filename": "remote-control-2.4.1-x64.msi",
          "signatureRequired": true
        }
      ]
    },
    "linux-x64": {
      "artifacts": [
        {
          "format": "appimage",
          "url": "https://downloads.example.com/remote-control-2.4.1-x64.AppImage",
          "sha256": "64 lowercase or uppercase hex characters",
          "size": 160000000
        },
        {
          "format": "deb",
          "url": "https://downloads.example.com/remote-control-2.4.1-x64.deb",
          "sha256": "64 lowercase or uppercase hex characters",
          "size": 155000000,
          "signatureRequired": true
        }
      ]
    }
  }
}
```

Supported platform keys are `windows-x64`, `windows-arm64`, `macos-x64`, `macos-arm64`, `linux-x64`, and `linux-arm64`. Supported manifest formats are `msi`, `exe`, `dmg`, `pkg`, `appimage`, `deb`, `rpm`, and `tar.gz`. The current release workflow builds and publishes only the formats configured by Tauri today: Windows `msi`, macOS `dmg` for Intel and Apple Silicon runners, Linux `deb`, and Linux `appimage`. RPM, Windows EXE, and macOS PKG remain schema-supported but are not production-published until the packaging pipeline builds and tests them.

## Artifact Selection

The updater selects artifacts deterministically from OS, architecture, distribution/package environment, and installation type.

- Windows MSI installs prefer MSI and do not silently migrate to EXE.
- Windows EXE installs prefer EXE and do not silently migrate to MSI.
- macOS app-bundle/DMG installs prefer DMG; PKG installs prefer PKG.
- Linux DEB installs prefer DEB, RPM installs prefer RPM, AppImage installs prefer AppImage, and portable archives prefer `tar.gz`.
- Unknown Linux installs prefer AppImage, then archive, then native packages only when explicitly compatible.

If an installed package format is no longer available, the updater blocks and explains the unsupported migration unless that artifact explicitly opts into `allowPackageMigration` and the client policy allows it. This avoids changing a system package install into a portable install without user-visible migration logic.

## OS Compatibility

`minimumOSVersion` is enforced before downloading. Windows supports build-based requirements such as Windows 10 build `19045` or Windows 11 build `22631`. macOS versions are compared semantically, such as `13.0`, `14.0`, and `15.0`. Linux uses explicit runtime requirements (`kernel`, `glibc`) instead of pretending there is a single Linux OS version. Unsupported machines get a compatibility error before any artifact bytes are downloaded.

## Runtime Flow

1. The UI calls `check_for_updates` with an index or manifest URL.
2. The backend detects OS, version/build, CPU architecture, installation architecture, Linux runtime details, and installation type.
3. The backend verifies signed release metadata, validates schemas, rejects unsafe URLs and paths, and selects the newest compatible release/artifact.
4. Disk space is checked for download, staging/extraction, installation, rollback backup, metadata, and a safety margin.
5. `download_update` streams to `*.part`, persists progress in `downloads.json`, retries transient failures, and resumes with HTTP Range when safe.
6. Completion requires exact byte count and SHA-256 match. Corrupt downloads are deleted and never installed.
7. Required package signatures are verified.
8. The backend enters `ReadyToInstall`; installation cannot start until the user explicitly invokes `install_update`.
9. Native installers handle `.msi`, `.exe`, `.dmg`, `.pkg`, `.deb`, `.rpm`, and `.AppImage`. Archive/bundle replacement uses `rc-updater-helper`.
10. Staged helper updates persist transaction state, move the old app to backup, move the staged app into place, launch the new version, and require an `UPDATE_BOOT_OK` JSON handshake with transaction ID and expected version. Backup cleanup happens only after that health check succeeds.

## Bootstrapper Flow

`cargo run -p rc-updater --bin rc-bootstrapper -- --metadata-url <signed-index-or-manifest>` provides a real fresh-install path for machines without the app installed. It reuses the same signed metadata verification, platform selection, download queue, SHA-256 verification, package signature verification, disk-space checks, and native installer code. It prints real byte progress from backend download events and asks the user to type `install` before launching the installer.

## Release Pipeline

`.github/workflows/release.yml` runs on `v*.*.*` tags. It fails if the tag version and project versions drift. The build matrix produces Windows MSI, macOS DMG on Intel and Apple Silicon runners, Linux DEB, and Linux AppImage. The publish job waits for all matrix jobs, validates that downloaded assets exist and match their recorded sizes and hashes, derives release notes from the commits since the previous tag, generates deterministic `release-manifest.json`, signs those exact bytes, generates/signed `release-index.json` including the previous index when available, verifies signatures with configured public keys, and then publishes artifacts plus metadata to GitHub Releases.

`scripts/generate-release-notes.mjs` groups commits since the previous tag by conventional-commit type into Features, Fixes, Performance, Security and Other changes, dropping purely internal types such as `chore` and `ci`. The result is embedded in the manifest as `releaseNotes` and reused as the GitHub Release body, so the in-app "What's new" list and the release page always agree.

`.github/workflows/ci.yml` runs the same verification on every pull request and on `main`: version sync, Prettier, ESLint, TypeScript, Vitest, `cargo fmt`, Clippy with warnings denied, and the full Rust test suite.

Production macOS signing/notarization and Windows Authenticode require external credentials. The workflow and updater are structured for those secrets, but this repository does not contain them. Production release jobs should set policy variables to require signing before publication; unsigned builds must not be presented as production-signed releases.

## Testing

`cargo test -p rc-updater` covers semantic versions, strict manifest validation, release-index compatibility selection, URL policy, multiple artifact selection, package migration blocking, Windows build and macOS version compatibility, downloader retries/resume/cancellation/corruption handling, persistent state recovery, checksum rejection, metadata signature verification with key rotation, Windows installer exit-code classification, state-machine transition enforcement, full AppImage install path reuse, staged update health checks, rollback, and cleanup.

`crates/updater/tests/release_metadata_interop.rs` pins the contract between the Node signing scripts and the Rust verifier using fixtures produced by the real release scripts and signed with the production key. It asserts that genuine metadata verifies, and that tampered bytes, an untrusted key, an empty keyring and a missing signature are all rejected.

`cargo test -p rc-desktop-client` covers the command layer: metadata-URL precedence, the compiled-in keyring being present and well formed, the signature policy being `Required`, config persistence and recovery from a corrupt config, URL redaction in logs, progress clamping, and that a failed install leaves a state the user can retry from.

`pnpm --filter @rc/desktop-client test:run` covers the update UI rules: one action per backend state, when a background check may run, when an update is advertised in the shell, which transfer controls apply, and release-note parsing.

Normal local verification does not perform privileged OS installation. Package and install smoke tests are isolated to CI runners or explicit local commands so a developer workstation is not modified unexpectedly.
