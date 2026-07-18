//! Deterministic environment identity and discovery labels.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::{Project, ProjectId};
use crate::error::NamingError;
use crate::git::GitContext;
use crate::naming::{DnsLabel, Hostname, IpDnsDomain};

/// Resource label marking an object as managed by Lightrail.
pub const LABEL_MANAGED: &str = "lightrail-managed";
/// Resource label containing the immutable project UUID.
pub const LABEL_PROJECT_ID: &str = "lightrail-project-id";
/// Resource label containing the normalized project slug.
pub const LABEL_PROJECT: &str = "lightrail-project";
/// Resource label containing the environment identifier.
pub const LABEL_ENVIRONMENT_ID: &str = "lightrail-environment-id";
/// Resource label containing the normalized profile.
pub const LABEL_PROFILE: &str = "lightrail-profile";
/// Resource label containing the normalized Git branch or detached-HEAD name.
pub const LABEL_BRANCH: &str = "lightrail-branch";

const ENVIRONMENT_ID_PREFIX: &str = "lr-";
const ENVIRONMENT_DIGEST_BYTES: usize = 12;
const ENVIRONMENT_HASH_DOMAIN: &[u8] = b"lightrail/environment/v1\0";

/// A deterministic, provider-safe environment identifier.
///
/// The identifier uses 96 bits of a domain-separated SHA-256 digest and is
/// stable for the tuple `(project UUID, profile, raw branch)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// Returns the provider-safe identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Provider-independent identity of one profile/branch environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvironmentIdentity {
    project_id: ProjectId,
    project: String,
    profile: String,
    branch: String,
    project_label: DnsLabel,
    profile_label: DnsLabel,
    branch_label: DnsLabel,
    id: EnvironmentId,
}

impl EnvironmentIdentity {
    /// Creates an identity from committed project metadata and raw checkout state.
    ///
    /// Project slugs affect human-facing hostnames and labels but deliberately do
    /// not affect the environment ID. Renaming a project therefore does not
    /// orphan its provider resources.
    ///
    /// # Errors
    ///
    /// Returns [`NamingError`] for a nil project UUID or an empty semantic name.
    pub fn new(
        project_id: ProjectId,
        project: impl Into<String>,
        profile: impl Into<String>,
        branch: impl Into<String>,
    ) -> Result<Self, NamingError> {
        if project_id.as_uuid().is_nil() {
            return Err(NamingError::NilProjectId);
        }

        let project = project.into();
        let profile = profile.into();
        let branch = branch.into();
        ensure_non_empty("project", &project)?;
        ensure_non_empty("profile", &profile)?;
        ensure_non_empty("branch", &branch)?;

        let project_label = DnsLabel::new(&project)?;
        let profile_label = DnsLabel::new(&profile)?;
        let branch_label = DnsLabel::new(&branch)?;
        let id = derive_environment_id(project_id, &profile, &branch);

        Ok(Self {
            project_id,
            project,
            profile,
            branch,
            project_label,
            profile_label,
            branch_label,
            id,
        })
    }

    /// Creates an identity from a validated project and discovered Git checkout.
    ///
    /// # Errors
    ///
    /// Returns [`NamingError`] when project or checkout identity inputs are
    /// empty or invalid.
    pub fn from_git(
        project: &Project,
        profile: impl Into<String>,
        git: &GitContext,
    ) -> Result<Self, NamingError> {
        Self::new(
            project.id,
            project.slug.clone(),
            profile,
            git.branch().to_owned(),
        )
    }

    /// Returns the immutable project identity.
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    /// Returns the raw project slug.
    #[must_use]
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Returns the raw profile name.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Returns the raw branch name or detached-HEAD identifier.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Returns the deterministic environment ID.
    #[must_use]
    pub const fn id(&self) -> &EnvironmentId {
        &self.id
    }

    /// Returns the normalized branch DNS label.
    #[must_use]
    pub const fn branch_label(&self) -> &DnsLabel {
        &self.branch_label
    }

    /// Returns the normalized profile DNS label.
    #[must_use]
    pub const fn profile_label(&self) -> &DnsLabel {
        &self.profile_label
    }

    /// Returns the normalized project DNS label.
    #[must_use]
    pub const fn project_label(&self) -> &DnsLabel {
        &self.project_label
    }

    /// Builds the mandatory branch-first/app-second hostname for one app.
    ///
    /// # Errors
    ///
    /// Returns [`NamingError`] when the app is empty or the resulting DNS name
    /// exceeds the protocol limit.
    pub fn hostname(
        &self,
        app: &str,
        address: Ipv4Addr,
        domain: IpDnsDomain,
    ) -> Result<Hostname, NamingError> {
        ensure_non_empty("app", app)?;
        let app = DnsLabel::new(app)?;
        Hostname::new(
            &self.branch_label,
            &app,
            &self.profile_label,
            &self.project_label,
            address,
            domain,
        )
    }

    /// Returns the common-denominator labels used to rediscover resources.
    ///
    /// Every value is lowercase ASCII and at most 63 bytes, making the result
    /// suitable for Docker, Kubernetes, and conservative cloud label systems.
    #[must_use]
    pub fn resource_labels(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (LABEL_MANAGED, "true".to_owned()),
            (LABEL_PROJECT_ID, self.project_id.simple()),
            (LABEL_PROJECT, self.project_label.as_str().to_owned()),
            (LABEL_ENVIRONMENT_ID, self.id.as_str().to_owned()),
            (LABEL_PROFILE, self.profile_label.as_str().to_owned()),
            (LABEL_BRANCH, self.branch_label.as_str().to_owned()),
        ])
    }
}

fn ensure_non_empty(kind: &'static str, value: &str) -> Result<(), NamingError> {
    if value.is_empty() {
        Err(NamingError::Empty { kind })
    } else {
        Ok(())
    }
}

fn derive_environment_id(project_id: ProjectId, profile: &str, branch: &str) -> EnvironmentId {
    let mut hasher = Sha256::new();
    hasher.update(ENVIRONMENT_HASH_DOMAIN);
    hasher.update(project_id.as_uuid().as_bytes());
    hash_length_prefixed(&mut hasher, profile.as_bytes());
    hash_length_prefixed(&mut hasher, branch.as_bytes());
    let digest = hasher.finalize();
    EnvironmentId(format!(
        "{ENVIRONMENT_ID_PREFIX}{}",
        hex::encode(&digest[..ENVIRONMENT_DIGEST_BYTES])
    ))
}

fn hash_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    let length = u64::try_from(value.len()).expect("Rust slices cannot exceed u64::MAX bytes");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project_id() -> ProjectId {
        ProjectId::from_str("2f1c30f5-dce1-4a5c-a751-3a766f6b48ea").expect("UUID")
    }

    use std::str::FromStr;

    #[test]
    fn identity_is_deterministic_and_provider_safe() {
        let first = EnvironmentIdentity::new(project_id(), "myproject", "preview", "feature/login")
            .expect("identity");
        let second =
            EnvironmentIdentity::new(project_id(), "myproject", "preview", "feature/login")
                .expect("identity");

        assert_eq!(first.id(), second.id());
        assert_eq!(first.id().as_str().len(), 27);
        assert!(
            first
                .id()
                .as_str()
                .bytes()
                .all(|byte| { byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' })
        );
    }

    #[test]
    fn slug_does_not_change_identity_but_branch_and_profile_do() {
        let base = EnvironmentIdentity::new(project_id(), "old-name", "preview", "main")
            .expect("identity");
        let renamed = EnvironmentIdentity::new(project_id(), "new-name", "preview", "main")
            .expect("identity");
        let profile = EnvironmentIdentity::new(project_id(), "old-name", "staging", "main")
            .expect("identity");
        let branch = EnvironmentIdentity::new(project_id(), "old-name", "preview", "next")
            .expect("identity");

        assert_eq!(base.id(), renamed.id());
        assert_ne!(base.id(), profile.id());
        assert_ne!(base.id(), branch.id());
    }

    #[test]
    fn resource_labels_are_safe_and_stable() {
        let identity =
            EnvironmentIdentity::new(project_id(), "My Project", "Preview", "feature/login")
                .expect("identity");
        let labels = identity.resource_labels();

        assert_eq!(labels[LABEL_MANAGED], "true");
        assert_eq!(labels[LABEL_PROJECT_ID], project_id().simple());
        assert_eq!(labels[LABEL_ENVIRONMENT_ID], identity.id().as_str());
        assert!(labels.values().all(|value| {
            value.len() <= 63
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        }));
    }

    #[test]
    fn builds_hostnames_from_raw_app_names() {
        let identity =
            EnvironmentIdentity::new(project_id(), "myproject", "preview", "feature-login")
                .expect("identity");
        let hostname = identity
            .hostname(
                "frontend",
                Ipv4Addr::new(203, 0, 113, 10),
                IpDnsDomain::SslipIo,
            )
            .expect("hostname");

        assert_eq!(
            hostname.as_str(),
            "feature-login.frontend.preview.myproject.cb00710a.sslip.io"
        );
    }

    #[test]
    fn rejects_nil_project_identity() {
        let error = EnvironmentIdentity::new(
            ProjectId::from_uuid(uuid::Uuid::nil()),
            "project",
            "profile",
            "branch",
        )
        .expect_err("nil identity");

        assert_eq!(error, NamingError::NilProjectId);
    }
}
