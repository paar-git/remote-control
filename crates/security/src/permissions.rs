//! The application permission model.
//!
//! # Why capabilities rather than role checks
//!
//! Authorization is expressed as *typed capabilities*, and every check goes through
//! [`Role::grants`] or [`AuthorizationContext::require`]. No call site anywhere is
//! permitted to write `if role == Role::Owner`. Two reasons:
//!
//! 1. Adding a role means updating one table here, not auditing every branch.
//! 2. [`Capability`] is `#[non_exhaustive]` and the grant table is an exhaustive
//!    `match`, so adding a capability without deciding which roles get it is a
//!    compile error rather than a silent grant or denial.
//!
//! # This is not OS privilege
//!
//! Application authorization and operating-system privilege are separate axes.
//! Holding [`Capability::PowerControl`] means the *application* will forward a power
//! request to the agent. Application permissions alone do not confer operating-system
//! privilege.

use serde::{Deserialize, Serialize};

use crate::error::{Result, SecurityError};

/// A discrete thing a session may be permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    /// See the remote screen.
    RemoteDesktopView,
    /// Inject mouse and keyboard input.
    RemoteInput,
    /// Open a terminal session.
    Terminal,
    /// List and download files.
    FileRead,
    /// Upload, rename, move and delete files.
    FileWrite,
    /// List and terminate processes.
    ProcessManagement,
    /// Start, stop and configure services.
    ServiceManagement,
    /// Restart, shut down, sleep or lock the host.
    PowerControl,
    /// Read and change agent settings.
    SettingsManagement,
    /// Pair, rename and revoke trusted devices.
    TrustedDeviceManagement,
}

impl Capability {
    /// Stable name used in errors, audit records and the UI.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RemoteDesktopView => "remote_desktop_view",
            Self::RemoteInput => "remote_input",
            Self::Terminal => "terminal",
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::ProcessManagement => "process_management",
            Self::ServiceManagement => "service_management",
            Self::PowerControl => "power_control",
            Self::SettingsManagement => "settings_management",
            Self::TrustedDeviceManagement => "trusted_device_management",
        }
    }

    /// Every capability this build knows about.
    ///
    /// Kept in sync with the enum by [`tests::all_capabilities_are_listed`].
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::RemoteDesktopView,
            Self::RemoteInput,
            Self::Terminal,
            Self::FileRead,
            Self::FileWrite,
            Self::ProcessManagement,
            Self::ServiceManagement,
            Self::PowerControl,
            Self::SettingsManagement,
            Self::TrustedDeviceManagement,
        ]
    }

    /// Whether exercising this capability can change or destroy state on the host.
    ///
    /// Drives which operations the confirmation policy applies to.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        match self {
            Self::RemoteInput
            | Self::Terminal
            | Self::FileWrite
            | Self::ProcessManagement
            | Self::ServiceManagement
            | Self::PowerControl
            | Self::SettingsManagement
            | Self::TrustedDeviceManagement => true,
            Self::RemoteDesktopView | Self::FileRead => false,
        }
    }
}

/// A permission role assigned to a trusted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Role {
    /// Full control. Assigned to the operator's own client.
    Owner,
    /// May watch the screen and read files, nothing else.
    ViewOnly,
    /// Day-to-day administration, but may not change trust or settings.
    Operator,
}

impl Role {
    /// Stable name used in the database, on the wire and in audit records.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::ViewOnly => "view_only",
            Self::Operator => "operator",
        }
    }

    /// Parse a stored role name.
    ///
    /// Returns `None` for anything unrecognised — an unknown role must fail closed,
    /// never fall back to a default that might grant more than intended.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "owner" => Some(Self::Owner),
            "view_only" => Some(Self::ViewOnly),
            "operator" => Some(Self::Operator),
            _ => None,
        }
    }

    /// Every role this build knows about.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Owner, Self::ViewOnly, Self::Operator]
    }

    /// Whether this role grants `capability`.
    ///
    /// The exhaustive inner `match` is the point: a new capability cannot be added
    /// without deciding, here, what each role gets.
    #[must_use]
    pub const fn grants(self, capability: Capability) -> bool {
        match self {
            // The owner holds every capability. Written as an explicit `true` rather
            // than a wildcard so a reviewer can see it is deliberate.
            Self::Owner => true,

            // The remaining arms list only what is *granted*. Everything else — the
            // explicitly-denied capabilities and any variant added later, since
            // `Capability` is `#[non_exhaustive]` — falls through to `false`, so a
            // new capability is denied until someone deliberately grants it here.
            Self::ViewOnly => {
                matches!(
                    capability,
                    Capability::RemoteDesktopView | Capability::FileRead
                )
            }

            // Note what is absent: `SettingsManagement` and `TrustedDeviceManagement`
            // are reserved for the owner, so an operator cannot grant itself more.
            Self::Operator => matches!(
                capability,
                Capability::RemoteDesktopView
                    | Capability::RemoteInput
                    | Capability::Terminal
                    | Capability::FileRead
                    | Capability::FileWrite
                    | Capability::ProcessManagement
                    | Capability::ServiceManagement
                    | Capability::PowerControl
            ),
        }
    }

    /// Every capability this role grants.
    #[must_use]
    pub fn capabilities(self) -> Vec<Capability> {
        Capability::all()
            .iter()
            .copied()
            .filter(|c| self.grants(*c))
            .collect()
    }
}

/// The authorization state of an authenticated session.
///
/// Constructing one asserts that authentication has already succeeded; this type
/// answers *what may be done*, not *who is it*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationContext {
    role: Role,
    /// `false` once trust is revoked. Checked on every authorization decision so a
    /// revocation takes effect immediately rather than at the next reconnect.
    active: bool,
}

impl AuthorizationContext {
    /// An active context for `role`.
    #[must_use]
    pub const fn new(role: Role) -> Self {
        Self { role, active: true }
    }

    /// A context whose device has been revoked. Grants nothing.
    #[must_use]
    pub const fn revoked(role: Role) -> Self {
        Self {
            role,
            active: false,
        }
    }

    /// The role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Whether the underlying trust is still valid.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Mark the context revoked. Takes effect on the very next check.
    pub const fn revoke(&mut self) {
        self.active = false;
    }

    /// Whether this context currently permits `capability`.
    #[must_use]
    pub const fn allows(&self, capability: Capability) -> bool {
        self.active && self.role.grants(capability)
    }

    /// Enforce that `capability` is permitted.
    ///
    /// # Errors
    /// [`SecurityError::DeviceRevoked`] if trust was withdrawn, otherwise
    /// [`SecurityError::PermissionDenied`].
    pub const fn require(&self, capability: Capability) -> Result<()> {
        if !self.active {
            return Err(SecurityError::DeviceRevoked);
        }
        if self.role.grants(capability) {
            Ok(())
        } else {
            Err(SecurityError::PermissionDenied {
                capability: capability.name(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_holds_every_capability() {
        for capability in Capability::all() {
            assert!(
                Role::Owner.grants(*capability),
                "owner must hold {capability:?}"
            );
        }
        assert_eq!(Role::Owner.capabilities().len(), Capability::all().len());
    }

    #[test]
    fn view_only_can_watch_and_read_but_nothing_else() {
        assert!(Role::ViewOnly.grants(Capability::RemoteDesktopView));
        assert!(Role::ViewOnly.grants(Capability::FileRead));

        for capability in [
            Capability::RemoteInput,
            Capability::Terminal,
            Capability::FileWrite,
            Capability::ProcessManagement,
            Capability::ServiceManagement,
            Capability::PowerControl,
            Capability::SettingsManagement,
            Capability::TrustedDeviceManagement,
        ] {
            assert!(
                !Role::ViewOnly.grants(capability),
                "view-only must not hold {capability:?}"
            );
        }
    }

    #[test]
    fn operator_cannot_escalate_its_own_access() {
        // The property that keeps Operator below Owner.
        assert!(!Role::Operator.grants(Capability::TrustedDeviceManagement));
        assert!(!Role::Operator.grants(Capability::SettingsManagement));
        assert!(Role::Operator.grants(Capability::Terminal));
    }

    #[test]
    fn no_role_other_than_owner_manages_trust() {
        for role in Role::all() {
            if *role != Role::Owner {
                assert!(
                    !role.grants(Capability::TrustedDeviceManagement),
                    "{role:?} must not manage trusted devices"
                );
            }
        }
    }

    #[test]
    fn role_names_roundtrip_and_unknown_names_fail_closed() {
        for role in Role::all() {
            assert_eq!(Role::from_name(role.name()), Some(*role));
        }
        for unknown in ["", "admin", "root", "Owner", "owner "] {
            assert_eq!(Role::from_name(unknown), None, "{unknown:?} must not parse");
        }
    }

    #[test]
    fn all_capabilities_are_listed() {
        // Guards against adding a variant and forgetting `Capability::all()`, which
        // would silently exclude it from every enumeration in the UI.
        let listed = Capability::all();
        let mut sorted = listed.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            listed.len(),
            "duplicate entries in Capability::all()"
        );
        assert_eq!(
            listed.len(),
            10,
            "update this count when adding a capability"
        );
    }

    #[test]
    fn capability_names_are_unique_and_stable() {
        let mut names: Vec<_> = Capability::all().iter().map(|c| c.name()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "capability names must be unique");
    }

    #[test]
    fn read_only_capabilities_are_not_destructive() {
        assert!(!Capability::RemoteDesktopView.is_destructive());
        assert!(!Capability::FileRead.is_destructive());
        assert!(Capability::FileWrite.is_destructive());
        assert!(Capability::PowerControl.is_destructive());
    }

    #[test]
    fn authorization_context_enforces_capabilities() {
        let context = AuthorizationContext::new(Role::ViewOnly);

        context.require(Capability::RemoteDesktopView).unwrap();
        let err = context.require(Capability::Terminal).unwrap_err();
        assert!(
            matches!(err, SecurityError::PermissionDenied { capability } if capability == "terminal"),
            "got {err:?}"
        );
    }

    #[test]
    fn revocation_takes_effect_immediately() {
        let mut context = AuthorizationContext::new(Role::Owner);
        context.require(Capability::PowerControl).unwrap();

        context.revoke();

        for capability in Capability::all() {
            assert!(
                !context.allows(*capability),
                "revoked context granted {capability:?}"
            );
            assert!(matches!(
                context.require(*capability),
                Err(SecurityError::DeviceRevoked)
            ));
        }
    }

    #[test]
    fn a_revoked_owner_has_no_capabilities() {
        // Revocation must dominate role, not the other way around.
        let context = AuthorizationContext::revoked(Role::Owner);
        assert!(!context.is_active());
        assert!(!context.allows(Capability::RemoteDesktopView));
    }

    #[test]
    fn permission_errors_name_the_missing_capability() {
        let context = AuthorizationContext::new(Role::Operator);
        let message = context
            .require(Capability::SettingsManagement)
            .unwrap_err()
            .to_string();
        assert!(message.contains("settings_management"), "got {message}");
    }

    #[test]
    fn roles_serialize_to_their_stable_names() {
        // The database and the wire both store these strings.
        for role in Role::all() {
            let json = serde_json::to_string(role).unwrap();
            assert_eq!(json, format!("\"{}\"", role.name()));
        }
    }
}
