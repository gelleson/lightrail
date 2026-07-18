//! Deterministic DNS and provider-safe naming.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::NamingError;

/// Maximum number of bytes in one DNS label.
pub const DNS_LABEL_MAX_BYTES: usize = 63;
/// Maximum number of bytes in a fully-qualified DNS name without a trailing dot.
pub const DNS_NAME_MAX_BYTES: usize = 253;

const SHORT_HASH_HEX_BYTES: usize = 8;
const HASH_SEPARATOR_BYTES: usize = 1;
const HASHED_LABEL_PREFIX_MAX_BYTES: usize =
    DNS_LABEL_MAX_BYTES - SHORT_HASH_HEX_BYTES - HASH_SEPARATOR_BYTES;

/// A lowercase DNS-safe label whose encoded size is at most 63 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DnsLabel(String);

impl DnsLabel {
    /// Normalizes an arbitrary semantic name into a collision-safe DNS label.
    ///
    /// Invalid character runs become one hyphen. If normalization changes the
    /// input, or truncation is necessary, the first eight hexadecimal
    /// characters of the input's SHA-256 digest are appended.
    ///
    /// # Errors
    ///
    /// Returns [`NamingError::Empty`] when `value` is empty.
    pub fn new(value: &str) -> Result<Self, NamingError> {
        if value.is_empty() {
            return Err(NamingError::Empty { kind: "DNS label" });
        }

        let mut normalized = String::with_capacity(value.len().min(DNS_LABEL_MAX_BYTES));
        let mut pending_separator = false;

        for character in value.chars() {
            if character.is_ascii_alphanumeric() {
                if pending_separator && !normalized.is_empty() {
                    normalized.push('-');
                }
                normalized.push(character.to_ascii_lowercase());
                pending_separator = false;
            } else {
                pending_separator = true;
            }
        }

        if normalized.is_empty() {
            return Err(NamingError::Empty {
                kind: "normalized DNS label",
            });
        }

        let changed = normalized != value;
        let truncated = normalized.len() > DNS_LABEL_MAX_BYTES;
        if changed || truncated {
            normalized.truncate(normalized.len().min(HASHED_LABEL_PREFIX_MAX_BYTES));
            while normalized.ends_with('-') {
                normalized.pop();
            }
            if normalized.is_empty() {
                normalized.push('x');
            }
            normalized.push('-');
            normalized.push_str(&short_sha256(value.as_bytes()));
        }

        debug_assert!(!normalized.is_empty());
        debug_assert!(normalized.len() <= DNS_LABEL_MAX_BYTES);
        debug_assert!(
            normalized
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
        debug_assert!(normalized.as_bytes()[0].is_ascii_alphanumeric());
        debug_assert!(
            normalized
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        );

        Ok(Self(normalized))
    }

    /// Returns the normalized label.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DnsLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The supported embedded-IP DNS suffixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpDnsDomain {
    /// `sslip.io`
    #[serde(rename = "sslip.io")]
    SslipIo,
    /// `nip.io`
    #[serde(rename = "nip.io")]
    NipIo,
}

impl IpDnsDomain {
    /// Returns the canonical DNS suffix.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SslipIo => "sslip.io",
            Self::NipIo => "nip.io",
        }
    }
}

impl fmt::Display for IpDnsDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for IpDnsDomain {
    type Err = NamingError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sslip.io" => Ok(Self::SslipIo),
            "nip.io" => Ok(Self::NipIo),
            _ => Err(NamingError::UnsupportedIpDnsDomain(value.to_owned())),
        }
    }
}

/// Converts IPv4 octets to exactly eight lowercase hexadecimal characters.
#[must_use]
pub fn ipv4_hex(address: Ipv4Addr) -> String {
    hex::encode(address.octets())
}

/// A complete, validated Lightrail application hostname.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Hostname(String);

impl Hostname {
    /// Creates a hostname in the required branch-first/app-second order.
    ///
    /// # Errors
    ///
    /// Returns [`NamingError::DnsNameTooLong`] when the complete name exceeds
    /// 253 bytes.
    pub fn new(
        branch: &DnsLabel,
        app: &DnsLabel,
        profile: &DnsLabel,
        project: &DnsLabel,
        address: Ipv4Addr,
        domain: IpDnsDomain,
    ) -> Result<Self, NamingError> {
        let hostname = format!(
            "{branch}.{app}.{profile}.{project}.{}.{domain}",
            ipv4_hex(address)
        );
        if hostname.len() > DNS_NAME_MAX_BYTES {
            return Err(NamingError::DnsNameTooLong {
                length: hostname.len(),
                maximum: DNS_NAME_MAX_BYTES,
            });
        }
        Ok(Self(hostname))
    }

    /// Returns the complete hostname.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the mandatory HTTPS URL for this hostname.
    #[must_use]
    pub fn https_url(&self) -> String {
        format!("https://{}", self.0)
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

fn short_sha256(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex::encode(&digest[..SHORT_HASH_HEX_BYTES / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv4_as_exact_lowercase_hex() {
        let address = Ipv4Addr::new(203, 0, 113, 10);
        assert_eq!(ipv4_hex(address), "cb00710a");
    }

    #[test]
    fn valid_label_is_unchanged() {
        assert_eq!(
            DnsLabel::new("feature-login")
                .expect("valid label")
                .as_str(),
            "feature-login"
        );
    }

    #[test]
    fn normalized_labels_cannot_collide_with_a_literal_label() {
        let slash = DnsLabel::new("feature/login").expect("normalizable label");
        let hyphen = DnsLabel::new("feature-login").expect("valid label");

        assert!(slash.as_str().starts_with("feature-login-"));
        assert_ne!(slash, hyphen);
        assert_eq!(slash.as_str().len(), "feature-login-".len() + 8);
    }

    #[test]
    fn normalization_is_stable_and_dns_safe() {
        let first = DnsLabel::new("///Feature___LOGIN///").expect("normalizable label");
        let second = DnsLabel::new("///Feature___LOGIN///").expect("normalizable label");

        assert_eq!(first, second);
        assert!(first.as_str().starts_with("feature-login-"));
        assert!(first.as_str().len() <= DNS_LABEL_MAX_BYTES);
        assert!(
            first
                .as_str()
                .bytes()
                .all(|byte| { byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' })
        );
    }

    #[test]
    fn long_labels_are_truncated_with_a_hash() {
        let label = DnsLabel::new(&"a".repeat(100)).expect("long label");

        assert_eq!(label.as_str().len(), DNS_LABEL_MAX_BYTES);
        assert!(label.as_str().starts_with(&"a".repeat(54)));
    }

    #[test]
    fn rejects_a_label_with_no_dns_characters() {
        assert!(matches!(
            DnsLabel::new("///___"),
            Err(NamingError::Empty { .. })
        ));
    }

    #[test]
    fn constructs_exact_branch_first_hostname() {
        let hostname = Hostname::new(
            &DnsLabel::new("feature-login").expect("branch"),
            &DnsLabel::new("frontend").expect("app"),
            &DnsLabel::new("preview").expect("profile"),
            &DnsLabel::new("myproject").expect("project"),
            Ipv4Addr::new(203, 0, 113, 10),
            IpDnsDomain::SslipIo,
        )
        .expect("hostname");

        assert_eq!(
            hostname.as_str(),
            "feature-login.frontend.preview.myproject.cb00710a.sslip.io"
        );
        assert_eq!(
            hostname.https_url(),
            "https://feature-login.frontend.preview.myproject.cb00710a.sslip.io"
        );
    }

    #[test]
    fn rejects_names_over_the_total_dns_limit() {
        let label = DnsLabel::new(&"a".repeat(63)).expect("label");
        let error = Hostname::new(
            &label,
            &label,
            &label,
            &label,
            Ipv4Addr::LOCALHOST,
            IpDnsDomain::SslipIo,
        )
        .expect_err("complete name should be too long");

        assert!(matches!(error, NamingError::DnsNameTooLong { .. }));
    }
}
