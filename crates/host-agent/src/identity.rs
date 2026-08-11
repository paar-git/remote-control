//! Agent identity.
//!
//! These back the `identity` subcommand and the agent's own start-up: loading or
//! creating the device keystore, renewing the certificate, and recording that in the
//! audit trail.

use anyhow::Context as _;
use rc_security::{Clock, DeviceIdentity, Keystore, SystemClock};
use rc_storage::audit::{AuditCategory, AuditEvent, AuditRepository, AuditResult, actions};

use crate::config::AgentConfig;

/// How the identity returned by [`load_identity`] came to be.
///
/// The caller needs this to audit correctly: creating an identity is a one-time,
/// security-significant event, whereas loading one happens on every start and would
/// drown the trail if recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOrigin {
    /// No keystore existed; a new identity was generated.
    Created,
    /// An existing identity was loaded unchanged.
    Loaded,
    /// An existing identity was loaded and its certificate reissued. The device id and
    /// identity fingerprint are unchanged, so trust is preserved.
    CertificateRenewed,
}

/// Load the agent's identity, creating it on first run.
///
/// Returns the identity together with how it was obtained, so the caller can write the
/// matching audit record once the database is open.
///
/// # Errors
/// Fails if the keystore is corrupt, has unsafe permissions, or was written under a
/// different OS identity. It never silently regenerates: doing so would change the
/// agent's identity and break every existing pairing.
pub fn load_identity(
    paths: &rc_platform::AppPaths,
    config: &AgentConfig,
) -> anyhow::Result<(DeviceIdentity, IdentityOrigin)> {
    let keystore = Keystore::in_data_dir(paths.data_dir());
    let clock = SystemClock;

    // Sampled before `load_or_create`, which is what makes creation distinguishable
    // from an ordinary load.
    let existed = keystore.exists();

    let identity = keystore
        .load_or_create(&config.device_name, &clock)
        .context("could not load or create the agent identity")?;

    // A certificate that has expired, or is about to, is renewed in place. The device
    // id and identity fingerprint are preserved, so paired clients are unaffected.
    let public = identity.public();
    if existed && public.needs_renewal_at(clock.now_ms()) {
        tracing::info!(
            expires_at_ms = public.certificate_not_after_ms,
            "certificate is due for renewal; issuing a new one"
        );
        let renewed = identity
            .renew_certificate(&config.device_name, &clock)
            .context("could not renew the device certificate")?;
        keystore
            .store(&renewed, &config.device_name, &clock)
            .context("could not persist the renewed certificate")?;
        return Ok((renewed, IdentityOrigin::CertificateRenewed));
    }

    let origin = if existed {
        IdentityOrigin::Loaded
    } else {
        IdentityOrigin::Created
    };
    Ok((identity, origin))
}

/// Write the audit record for how the identity was obtained.
///
/// A plain load produces no record: it happens on every start, and a trail that logs
/// every boot buries the events that matter. Only creation and renewal are recorded,
/// and neither carries key material — the device id and identity fingerprint are both
/// public values a client is expected to see.
///
/// # Errors
/// Propagates a failure to write the audit row. Identity creation that cannot be
/// audited is treated as a failure rather than proceeding silently.
pub async fn record_identity_event(
    audit: &AuditRepository,
    origin: IdentityOrigin,
    identity: &DeviceIdentity,
    clock: &dyn Clock,
) -> anyhow::Result<()> {
    let action = match origin {
        IdentityOrigin::Loaded => return Ok(()),
        IdentityOrigin::Created => actions::IDENTITY_CREATED,
        IdentityOrigin::CertificateRenewed => actions::CERTIFICATE_RENEWED,
    };

    let public = identity.public();
    audit
        .record(
            &AuditEvent::new(AuditCategory::Config, action, AuditResult::Success)
                .actor_device(public.device_id)
                .meta("identity_fingerprint", public.identity_fingerprint)
                .meta("certificate_version", public.certificate_version),
            clock.now_ms(),
        )
        .await
        .context("could not write the identity audit record")?;

    Ok(())
}

/// Print this agent's identity for the operator to compare.
pub fn print_identity(identity: &DeviceIdentity) {
    let public = identity.public();
    println!("Device ID:              {}", public.device_id);
    println!(
        "Identity fingerprint:   {}",
        public.identity_fingerprint.to_display_groups()
    );
    println!(
        "Certificate fingerprint: {}",
        public.certificate_fingerprint.to_display_groups()
    );
    println!("Certificate version:    {}", public.certificate_version);
    println!(
        "Certificate valid until: {}",
        format_timestamp(public.certificate_not_after_ms)
    );
    println!();
    println!("The identity fingerprint is what a client pins. It does not change when the");
    println!("certificate is renewed. Compare it with what your client displays.");
}

/// Format a millisecond timestamp for console output.
fn format_timestamp(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).map_or_else(
        || "unknown".to_string(),
        |dt| dt.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

#[cfg(test)]
mod tests {
    use rc_storage::audit::AuditCategory;

    use super::*;

    #[tokio::test]
    async fn creating_an_identity_is_audited_but_loading_one_is_not() {
        let database = rc_storage::Database::open_in_memory().await.unwrap();
        let audit = AuditRepository::new(&database);
        let clock = SystemClock;
        let identity = DeviceIdentity::generate("test-agent", &clock).unwrap();

        record_identity_event(&audit, IdentityOrigin::Loaded, &identity, &clock)
            .await
            .unwrap();
        assert_eq!(
            audit.count().await.unwrap(),
            0,
            "an ordinary load must not write a record on every boot"
        );

        record_identity_event(&audit, IdentityOrigin::Created, &identity, &clock)
            .await
            .unwrap();
        record_identity_event(
            &audit,
            IdentityOrigin::CertificateRenewed,
            &identity,
            &clock,
        )
        .await
        .unwrap();
        assert_eq!(audit.count().await.unwrap(), 2);

        // Neither record may carry key material.
        let rendered = format!("{:?}", audit.recent(10).await.unwrap());
        assert!(
            !rendered.contains("PRIVATE"),
            "no key material in the trail"
        );
        assert_eq!(
            audit
                .recent_in_category(AuditCategory::Pairing, 10)
                .await
                .unwrap()
                .len(),
            0,
            "identity events belong to the config category, not pairing"
        );
    }

    #[test]
    fn timestamps_render_readably() {
        let rendered = format_timestamp(1_700_000_000_000);
        assert!(rendered.starts_with("2023-11-14"), "got {rendered}");
        assert!(rendered.ends_with("UTC"));
    }

    #[test]
    fn an_impossible_timestamp_does_not_panic() {
        assert_eq!(format_timestamp(i64::MAX), "unknown");
    }
}
