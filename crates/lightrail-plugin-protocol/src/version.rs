use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;

/// Current Lightrail plugin protocol version.
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);

/// String form of [`PROTOCOL_VERSION`] for non-Rust tooling.
pub const PROTOCOL_VERSION_STRING: &str = "1.0.0";

/// A stable semantic protocol version.
///
/// Pre-release/build suffixes are deliberately not accepted. Protocol
/// negotiation uses only the ordered `major.minor.patch` core.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolVersion {
    /// Breaking-change component.
    pub major: u64,
    /// Backward-compatible feature component.
    pub minor: u64,
    /// Backward-compatible fix component.
    pub patch: u64,
}

impl ProtocolVersion {
    /// Construct a protocol version usable in constants.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for ProtocolVersion {
    type Err = VersionParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut components = value.split('.');
        let major = parse_component(components.next(), value)?;
        let minor = parse_component(components.next(), value)?;
        let patch = parse_component(components.next(), value)?;
        if components.next().is_some() {
            return Err(VersionParseError(value.to_owned()));
        }
        Ok(Self::new(major, minor, patch))
    }
}

fn parse_component(component: Option<&str>, original: &str) -> Result<u64, VersionParseError> {
    let component = component.ok_or_else(|| VersionParseError(original.to_owned()))?;
    if component.is_empty()
        || (component.len() > 1 && component.starts_with('0'))
        || !component.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(VersionParseError(original.to_owned()));
    }
    component
        .parse()
        .map_err(|_| VersionParseError(original.to_owned()))
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// Error returned for a non-canonical semantic protocol version.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("invalid protocol version `{0}`; expected canonical major.minor.patch")]
pub struct VersionParseError(pub String);

/// Half-open semantic-version range accepted by a plugin.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolRequirement {
    /// Oldest accepted version, inclusive.
    pub minimum: ProtocolVersion,
    /// First rejected version, exclusive. `None` means unbounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_exclusive: Option<ProtocolVersion>,
}

impl ProtocolRequirement {
    /// A range containing every version with the same major component.
    #[must_use]
    pub const fn compatible_with(version: ProtocolVersion) -> Self {
        Self {
            minimum: version,
            maximum_exclusive: Some(ProtocolVersion::new(version.major + 1, 0, 0)),
        }
    }

    /// Whether `version` is in this half-open range.
    #[must_use]
    pub fn contains(&self, version: ProtocolVersion) -> bool {
        version >= self.minimum
            && self
                .maximum_exclusive
                .is_none_or(|maximum| version < maximum)
    }
}

impl Default for ProtocolRequirement {
    fn default() -> Self {
        Self::compatible_with(PROTOCOL_VERSION)
    }
}

/// The exact version implemented by a plugin and the core versions it accepts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProtocolCompatibility {
    /// Exact wire version emitted by the plugin.
    pub version: ProtocolVersion,
    /// Core protocol versions with which the plugin can negotiate.
    pub requires: ProtocolRequirement,
}

impl Default for ProtocolCompatibility {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            requires: ProtocolRequirement::default(),
        }
    }
}
