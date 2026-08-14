//! What a session is allowed to do.
//!
//! Four permissions. Three are chosen by a human on the Accept dialog or pre-selected
//! for unattended access. The fourth, [`Permission::Administer`], is never reachable
//! from that dialog at all — it is granted only from a trusted device's own settings,
//! behind a confirmation that names the device.
//!
//! There are no roles: a role is an indirection that only pays for itself when there are
//! many permissions and many kinds of user, and this product has four of one and one of
//! the other.
//!
//! A permission is granted for the lifetime of a session and cannot be escalated
//! within it. Widening requires a new connection, which means a new decision by a
//! human — so a compromised session cannot talk its way into more than it was given.

use serde::{Deserialize, Serialize};

/// A discrete thing a session may be permitted to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Move the pointer and type on the remote machine.
    ControlInput,
    /// List, download and upload files.
    TransferFiles,
    /// Read CPU, memory, disk and network readings.
    ViewMetrics,
    /// Read and change this machine's trusted devices and their permissions.
    ///
    /// Deliberately separate from the other three, and from unattended access. A device
    /// permitted to reconnect without anyone approving has said nothing about whether it
    /// may rewrite the list of who else may, and a device permitted to move the mouse
    /// has said nothing either. Nothing implies this bit; it is always granted on its
    /// own.
    Administer,
}

impl Permission {
    /// Every permission, in the order the interface presents them.
    pub const ALL: [Self; 4] = [
        Self::ControlInput,
        Self::TransferFiles,
        Self::ViewMetrics,
        Self::Administer,
    ];

    /// Stable name used in errors, logs and the interface.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ControlInput => "control_input",
            Self::TransferFiles => "transfer_files",
            Self::ViewMetrics => "view_metrics",
            Self::Administer => "administer",
        }
    }

    /// This permission's bit in a [`PermissionSet`].
    const fn bit(self) -> u8 {
        match self {
            Self::ControlInput => 0b0000_0001,
            Self::TransferFiles => 0b0000_0010,
            Self::ViewMetrics => 0b0000_0100,
            Self::Administer => 0b0000_1000,
        }
    }
}

/// The permissions a session holds.
///
/// A bitset rather than a collection so it is `Copy` and can be carried on a session
/// without an allocation or a lock, and so an authorisation check is one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PermissionSet(u8);

impl PermissionSet {
    /// Every bit that any known permission uses.
    const KNOWN: u8 = 0b0000_1111;

    /// Grants nothing. What a connection holds before a human has decided.
    pub const NONE: Self = Self(0);

    /// Grants everything, [`Permission::Administer`] included.
    ///
    /// **Not** the Accept dialog's default selection: that dialog offers the three
    /// session permissions and strips `Administer` from whatever it returns.
    pub const ALL: Self = Self(Self::KNOWN);

    /// This set with `permission` added.
    #[must_use]
    pub const fn with(self, permission: Permission) -> Self {
        Self(self.0 | permission.bit())
    }

    /// This set with `permission` removed.
    #[must_use]
    pub const fn without(self, permission: Permission) -> Self {
        Self(self.0 & !permission.bit())
    }

    /// Whether this set grants `permission`.
    #[must_use]
    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Whether this set grants nothing at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The granted permissions, in [`Permission::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Permission> {
        Permission::ALL
            .into_iter()
            .filter(move |permission| self.contains(*permission))
    }

    /// The raw bits, for storage.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// A set from raw bits, or `None` if any unknown bit is set.
    ///
    /// Refusing rather than masking is deliberate. A peer or a database row carrying a
    /// permission this build does not know is not a set with one fewer permission — it
    /// is a value this build cannot interpret, and quietly reinterpreting it would make
    /// the same bytes mean different things on either side.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_set_grants_nothing() {
        let set = PermissionSet::NONE;
        assert!(set.is_empty());
        for permission in Permission::ALL {
            assert!(!set.contains(permission));
        }
    }

    #[test]
    fn all_grants_every_permission() {
        assert_eq!(Permission::ALL.len(), 4);
        for permission in Permission::ALL {
            assert!(PermissionSet::ALL.contains(permission));
        }
    }

    #[test]
    fn with_grants_only_the_named_permission() {
        let set = PermissionSet::NONE.with(Permission::TransferFiles);
        assert!(set.contains(Permission::TransferFiles));
        assert!(!set.contains(Permission::ControlInput));
        assert!(!set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn without_revokes_only_the_named_permission() {
        let set = PermissionSet::ALL.without(Permission::ControlInput);
        assert!(!set.contains(Permission::ControlInput));
        assert!(set.contains(Permission::TransferFiles));
        assert!(set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn with_is_idempotent() {
        let once = PermissionSet::NONE.with(Permission::ViewMetrics);
        assert_eq!(once, once.with(Permission::ViewMetrics));
    }

    #[test]
    fn iter_yields_exactly_the_granted_permissions() {
        let set = PermissionSet::NONE
            .with(Permission::ControlInput)
            .with(Permission::ViewMetrics);
        let granted: Vec<Permission> = set.iter().collect();
        assert_eq!(
            granted,
            vec![Permission::ControlInput, Permission::ViewMetrics]
        );
    }

    #[test]
    fn bits_round_trip() {
        let set = PermissionSet::NONE.with(Permission::TransferFiles);
        assert_eq!(PermissionSet::from_bits(set.bits()), Some(set));
    }

    #[test]
    fn unknown_bits_are_refused_rather_than_masked() {
        // A newer peer sending a permission this build does not know must not have it
        // silently dropped — the set would then mean something different on each side.
        assert_eq!(PermissionSet::from_bits(0b1000_0000), None);
    }

    #[test]
    fn names_are_stable() {
        assert_eq!(Permission::ControlInput.name(), "control_input");
        assert_eq!(Permission::TransferFiles.name(), "transfer_files");
        assert_eq!(Permission::ViewMetrics.name(), "view_metrics");
        assert_eq!(Permission::Administer.name(), "administer");
    }

    #[test]
    fn administer_is_a_permission_of_its_own() {
        let set = PermissionSet::NONE.with(Permission::Administer);
        assert!(set.contains(Permission::Administer));
        assert!(!set.contains(Permission::ControlInput));
        assert!(!set.contains(Permission::TransferFiles));
        assert!(!set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn no_other_permission_implies_administer() {
        // The separation the design rests on: nothing granted for ordinary remote
        // control may be read as authority over the trust database.
        for permission in [
            Permission::ControlInput,
            Permission::TransferFiles,
            Permission::ViewMetrics,
        ] {
            assert!(
                !PermissionSet::NONE
                    .with(permission)
                    .contains(Permission::Administer),
                "{} must not imply administer",
                permission.name()
            );
        }
    }

    #[test]
    fn removing_administer_leaves_the_rest_intact() {
        let set = PermissionSet::ALL.without(Permission::Administer);
        assert!(!set.contains(Permission::Administer));
        assert!(set.contains(Permission::ControlInput));
        assert!(set.contains(Permission::TransferFiles));
        assert!(set.contains(Permission::ViewMetrics));
    }

    #[test]
    fn the_administer_bit_is_known_and_bit_five_is_not() {
        assert_eq!(
            PermissionSet::from_bits(0b0000_1000),
            Some(PermissionSet::NONE.with(Permission::Administer))
        );
        assert_eq!(PermissionSet::from_bits(0b0001_0000), None);
    }
}
