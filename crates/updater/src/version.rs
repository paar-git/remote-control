use std::cmp::Ordering;

use semver::Version as SemverVersion;

use crate::error::{Result, UpdateError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub SemverVersion);

pub fn parse_version(value: &str) -> Result<Version> {
    SemverVersion::parse(value)
        .map(Version)
        .map_err(|_| UpdateError::InvalidVersion(value.to_string()))
}

pub fn compare_versions(left: &str, right: &str) -> Result<Ordering> {
    Ok(parse_version(left)?.cmp(&parse_version(right)?))
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use super::compare_versions;

    #[test]
    fn semantic_version_comparison_orders_releases() {
        assert_eq!(
            compare_versions("2.4.1", "2.4.0").unwrap(),
            Ordering::Greater
        );
        assert_eq!(compare_versions("2.4.0", "2.4.0").unwrap(), Ordering::Equal);
        assert_eq!(
            compare_versions("2.4.0-beta.1", "2.4.0").unwrap(),
            Ordering::Less
        );
    }

    #[test]
    fn invalid_versions_are_rejected() {
        assert!(compare_versions("2", "2.0.0").is_err());
    }
}
