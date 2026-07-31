# Keystore format

Secure, versioned storage for the device's private key material. Implemented in
`crates/security/src/keystore.rs`.

## File

A single JSON file, `device-identity.keystore`, in the agent's data directory.

```json
{
  "format_version": 1,
  "protection": "dpapi",
  "created_at_ms": 1700000000000,
  "device_created_at_ms": 1700000000000,
  "certificate_version": 1,
  "subject_name": "home-server",
  "identity_public_key": "<64 hex chars>",
  "payload": "<base64>",
  "integrity": "<64 hex chars>"
}
```

JSON is used deliberately: the file must remain **inspectable** by an operator diagnosing
a problem, while the one field that matters — `payload` — is either DPAPI-encrypted or
protected by file permissions. Nothing is both plaintext and unreadable.

| Field | Meaning |
|---|---|
| `format_version` | Envelope version. A file written by a newer build is refused outright. |
| `protection` | `dpapi` or `file_permissions`. |
| `created_at_ms` | When this keystore file was written. |
| `device_created_at_ms` | When the *identity key* was created. Survives certificate renewal. |
| `certificate_version` | Incremented on each renewal. |
| `subject_name` | Certificate subject, for operator recognition. |
| `identity_public_key` | Ed25519 public key. Public by definition. |
| `payload` | The protected private key material. |
| `integrity` | BLAKE3 keyed hash over a canonical encoding of every other field. |

### Versioning

`format_version` exists so a future change can *migrate* rather than guess. A file whose
version is higher than this build understands produces
`SecurityError::KeystoreVersionUnsupported` — the agent refuses to run rather than
misinterpreting key material.

### Integrity

`integrity` detects truncation, bit-rot and partial writes. It is **not** a defence
against an attacker who can write the file: the key is a fixed domain constant, not a
secret. Confidentiality and authenticity come from the protection mechanism.

## Protection mechanisms

| Platform | Mechanism | Protects against |
|---|---|---|
| Windows | DPAPI, `CurrentUser` scope | Any other local account reading the key, including other services |
| Linux/Unix | File mode `0600` in a `0700` directory | Any other local account reading the key |

### Windows: DPAPI

**`CurrentUser` scope is deliberate.** Machine scope would let every process on the host
decrypt the key, which defeats the purpose.

The consequence is that the keystore is **bound to the account that wrote it**:

* Changing the agent's service account requires re-running setup.
* Reading it as a different account produces `SecurityError::KeystoreWrongIdentity` — a
  clear, specific error, not a confusing parse failure.

An application-specific secondary entropy value (`dev.remotecontrol.keystore.v1`) is mixed
into DPAPI. Without it, *any* process running as the same user could decrypt the blob with
a bare `CryptUnprotectData` call. It is not a secret — it is a constant in the source —
but it raises the bar from "any process running as this user" to "a process written
against this application".

DPAPI is reached through the maintained `windows-dpapi` crate, which lets the security
crate keep `#![forbid(unsafe_code)]`.

#### Installer requirements

The installer must:

* Create the data directory owned by the agent's service account.
* Set an ACL granting **only** that account and `SYSTEM` access — no `Users`, no
  `Authenticated Users`.
* Run the agent under that same account, consistently. Changing it invalidates the
  keystore by design.

### Linux: file permissions

* Key file: mode `0600`.
* Parent directory: mode `0700`.

Unsafe permissions are a **hard error, not a warning**. A private key that is group- or
world-readable is already compromised; continuing would only hide that fact. The agent
refuses to start.

Writing an unprotected key is also refused on a platform that offers DPAPI, so a Windows
build cannot silently fall back to weaker protection.

### Atomic writes

The keystore is written to a temporary file in the same directory, then renamed over the
target. A crash mid-write leaves either the old file or the new one, never a truncated
one — which matters because a truncated keystore is an unrecoverable identity loss.

## Certificate renewal

Renewal reissues the TLS certificate **without changing the device identity**:

| Value | Derived from | Changes on renewal? |
|---|---|---|
| Device ID | Ed25519 identity public key | No |
| Identity fingerprint | SHA-256 of the identity public key | No |
| Certificate fingerprint | SHA-256 of the DER certificate | **Yes** |
| Certificate version | Counter | **Yes** |

Clients pin the **identity fingerprint**, so renewal does not break existing pairings.
The certificate fingerprint is expected to change and is recorded per-device so a rotation
can be distinguished from an identity substitution.

The agent never silently regenerates an identity. If the keystore cannot be read, it fails
— because regenerating would change the device identity and break every existing pairing,
which is a far worse outcome than a startup error.

## What this does not protect against

An attacker with offline access to an unencrypted disk can read a Unix keystore, and DPAPI
material is recoverable given the account's credentials. **Full-disk encryption is a
documented prerequisite** — see [`threat-model.md`](threat-model.md).

## Guarantees about private key material

Private keys never:

* Appear in logs — `DeviceIdentity`'s `Debug` impl redacts the signing key.
* Cross the Tauri IPC boundary to the frontend.
* Get stored in SQLite in any form.
* Appear in exported diagnostics.
* Get committed to Git — `.gitignore` covers keystores, certificates and databases.
