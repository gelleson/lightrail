use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use lightrail_plugin_protocol::{ErrorKind, OperationContext, PluginError, PluginResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MANAGED_LABEL: &str = "lightrail-managed";
pub const PROJECT_LABEL: &str = "lightrail-project";
pub const ENVIRONMENT_LABEL: &str = "lightrail-environment";
pub const CONFIG_LABEL: &str = "lightrail-config";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenReference {
    #[serde(default = "default_token_secret")]
    pub secret: String,
}

impl Default for TokenReference {
    fn default() -> Self {
        Self {
            secret: default_token_secret(),
        }
    }
}

fn default_token_secret() -> String {
    "hetzner-token".to_owned()
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapMode {
    #[default]
    #[serde(alias = "cloud-init")]
    Install,
    Verify,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub token: TokenReference,
    pub server_type: String,
    pub image: String,
    pub location: Option<String>,
    pub ssh_keys: Vec<String>,
    pub ssh_user: String,
    pub identity_file: Option<PathBuf>,
    pub allowed_ssh_cidrs: Vec<String>,
    pub bootstrap: BootstrapMode,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            token: TokenReference::default(),
            server_type: "cx23".to_owned(),
            image: "ubuntu-24.04".to_owned(),
            location: None,
            ssh_keys: Vec::new(),
            ssh_user: "root".to_owned(),
            identity_file: None,
            allowed_ssh_cidrs: Vec::new(),
            bootstrap: BootstrapMode::Install,
        }
    }
}

impl Settings {
    pub fn from_context(context: &OperationContext) -> PluginResult<Self> {
        let settings: Self = serde_json::from_value(context.config.clone()).map_err(|error| {
            PluginError::permanent(
                ErrorKind::Validation,
                "invalid_config",
                format!("invalid Hetzner target configuration: {error}"),
            )
        })?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> PluginResult<()> {
        if self.server_type.trim().is_empty() {
            return Err(validation(
                "server_type_required",
                "`server_type` must not be empty",
            ));
        }
        if !(self.image.starts_with("ubuntu-") || self.image.starts_with("debian-")) {
            return Err(validation(
                "unsupported_image",
                "`image` must be a supported Ubuntu or Debian image name",
            ));
        }
        if self.token.secret != "hetzner-token" {
            return Err(validation(
                "undeclared_token_secret",
                "`token.secret` must be `hetzner-token` in protocol version 1",
            ));
        }
        validate_ssh_user(&self.ssh_user)?;
        validate_cidrs(&self.allowed_ssh_cidrs)?;
        if let Some(identity_file) = &self.identity_file {
            validate_identity_file(identity_file)?;
        }
        if self.ssh_keys.is_empty() {
            return Err(validation(
                "ssh_key_required",
                "`ssh_keys` must contain at least one Hetzner SSH key name or ID; password bootstrap is not supported",
            ));
        }
        for key in &self.ssh_keys {
            if key.trim().is_empty() {
                return Err(validation(
                    "invalid_ssh_key",
                    "`ssh_keys` entries must not be empty",
                ));
            }
        }
        Ok(())
    }

    pub fn config_fingerprint(&self) -> String {
        #[derive(Serialize)]
        struct ProviderConfig<'a> {
            server_type: &'a str,
            image: &'a str,
            location: &'a Option<String>,
            ssh_keys: &'a [String],
            ssh_user: &'a str,
            bootstrap: BootstrapMode,
        }
        hash_json(&ProviderConfig {
            server_type: &self.server_type,
            image: &self.image,
            location: &self.location,
            ssh_keys: &self.ssh_keys,
            ssh_user: &self.ssh_user,
            bootstrap: self.bootstrap,
        })
    }
}

fn validate_identity_file(path: &Path) -> PluginResult<()> {
    if !path.is_absolute() {
        return Err(validation(
            "identity_file_not_absolute",
            "`identity_file` must be an absolute local path",
        ));
    }
    Ok(())
}

fn validate_ssh_user(user: &str) -> PluginResult<()> {
    let mut bytes = user.bytes();
    let Some(first) = bytes.next() else {
        return Err(validation(
            "invalid_ssh_user",
            "`ssh_user` must not be empty",
        ));
    };
    if user.len() > 32
        || !(first.is_ascii_lowercase() || first == b'_')
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        return Err(validation(
            "invalid_ssh_user",
            "`ssh_user` must be a safe Linux account name (lowercase, at most 32 characters)",
        ));
    }
    Ok(())
}

pub fn validate_cidrs(cidrs: &[String]) -> PluginResult<()> {
    if cidrs.is_empty() {
        return Err(validation(
            "ssh_cidrs_required",
            "`allowed_ssh_cidrs` is required; Lightrail will not open SSH to the world by default",
        ));
    }
    for cidr in cidrs {
        let (address, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| validation("invalid_ssh_cidr", format!("`{cidr}` is not an IP CIDR")))?;
        let address: IpAddr = address
            .parse()
            .map_err(|_| validation("invalid_ssh_cidr", format!("`{cidr}` is not an IP CIDR")))?;
        let prefix: u8 = prefix.parse().map_err(|_| {
            validation(
                "invalid_ssh_cidr",
                format!("`{cidr}` has an invalid prefix length"),
            )
        })?;
        let maximum = if address.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(validation(
                "invalid_ssh_cidr",
                format!("`{cidr}` has an invalid prefix length"),
            ));
        }
        if prefix == 0 {
            return Err(validation(
                "world_open_ssh",
                format!("`{cidr}` would expose SSH to the entire internet"),
            ));
        }
        let host_bits_set = match address {
            IpAddr::V4(address) if prefix < 32 => {
                let host_mask = (1_u32 << (32 - prefix)) - 1;
                u32::from(address) & host_mask != 0
            }
            IpAddr::V6(address) if prefix < 128 => {
                let host_mask = (1_u128 << (128 - prefix)) - 1;
                u128::from(address) & host_mask != 0
            }
            IpAddr::V4(_) | IpAddr::V6(_) => false,
        };
        if host_bits_set {
            return Err(validation(
                "non_canonical_ssh_cidr",
                format!("`{cidr}` has host bits set; use the canonical network address"),
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceIdentity {
    pub project_id: String,
    pub environment_id: String,
    pub project_label: String,
    pub environment_label: String,
    pub server_name: String,
    pub firewall_name: String,
    pub remote_root: String,
}

impl ResourceIdentity {
    pub fn from_context(context: &OperationContext) -> PluginResult<Self> {
        let project_id = project_id(&context.metadata).ok_or_else(|| {
            validation(
                "project_id_required",
                "operation metadata must contain the immutable `project_id`",
            )
        })?;
        if context.environment_id.trim().is_empty() {
            return Err(validation(
                "environment_id_required",
                "`environment_id` must not be empty",
            ));
        }
        let project_label = label_hash("p", &project_id);
        let environment_label = label_hash("e", &context.environment_id);
        let slug = project_slug(&context.metadata).unwrap_or_else(|| "project".to_owned());
        let suffix = short_hash(&context.environment_id, 12);
        let stem = dns_name(&format!("lr-{slug}-{suffix}"), 58);
        Ok(Self {
            project_id,
            environment_id: context.environment_id.clone(),
            project_label,
            environment_label: environment_label.clone(),
            server_name: stem.clone(),
            firewall_name: format!("{stem}-fw"),
            remote_root: format!("/opt/lightrail/{environment_label}"),
        })
    }

    pub fn labels(&self, config_fingerprint: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (MANAGED_LABEL.to_owned(), "true".to_owned()),
            (PROJECT_LABEL.to_owned(), self.project_label.clone()),
            (ENVIRONMENT_LABEL.to_owned(), self.environment_label.clone()),
            (
                CONFIG_LABEL.to_owned(),
                config_fingerprint[..config_fingerprint.len().min(32)].to_owned(),
            ),
        ])
    }

    pub fn environment_selector(&self) -> String {
        format!(
            "{MANAGED_LABEL}=true,{PROJECT_LABEL}={},{ENVIRONMENT_LABEL}={}",
            self.project_label, self.environment_label
        )
    }

    pub fn project_selector(&self) -> String {
        format!(
            "{MANAGED_LABEL}=true,{PROJECT_LABEL}={}",
            self.project_label
        )
    }
}

fn project_id(metadata: &Value) -> Option<String> {
    metadata
        .get("project_id")
        .and_then(Value::as_str)
        .or_else(|| {
            metadata
                .get("project")
                .and_then(|project| project.get("id"))
                .and_then(Value::as_str)
        })
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn project_slug(metadata: &Value) -> Option<String> {
    metadata
        .get("project_slug")
        .and_then(Value::as_str)
        .or_else(|| {
            metadata
                .get("project")
                .and_then(|project| project.get("slug"))
                .and_then(Value::as_str)
        })
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

fn label_hash(prefix: &str, value: &str) -> String {
    format!("{prefix}-{}", short_hash(value, 32))
}

pub fn short_hash(value: &str, length: usize) -> String {
    let digest = Sha256::digest(value.as_bytes());
    hex::encode(digest)[..length].to_owned()
}

fn dns_name(value: &str, maximum: usize) -> String {
    let mut output = String::with_capacity(value.len());
    let mut previous_hyphen = false;
    for character in value.chars() {
        let character = character.to_ascii_lowercase();
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
            previous_hyphen = false;
        } else if !previous_hyphen && !output.is_empty() {
            output.push('-');
            previous_hyphen = true;
        }
    }
    let output = output.trim_matches('-');
    let end = output
        .char_indices()
        .take_while(|(index, _)| *index < maximum)
        .last()
        .map_or(0, |(index, character)| index + character.len_utf8());
    output[..end].trim_matches('-').to_owned()
}

pub fn hash_json(value: &impl Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("serializable fingerprint input");
    hex::encode(Sha256::digest(encoded))
}

pub fn token<'a>(context: &'a OperationContext, settings: &Settings) -> PluginResult<&'a str> {
    context
        .secrets
        .get(&settings.token.secret)
        .map(lightrail_plugin_protocol::SecretValue::expose_secret)
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Authentication,
                "hetzner_token_required",
                "the `hetzner-token` secret is required",
            )
        })
}

pub fn validation(code: impl Into<String>, message: impl Into<String>) -> PluginError {
    PluginError::permanent(ErrorKind::Validation, code, message)
}

pub fn config_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "token": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "secret": { "const": "hetzner-token", "default": "hetzner-token" }
                },
                "default": { "secret": "hetzner-token" }
            },
            "server_type": {
                "type": "string",
                "minLength": 1,
                "default": "cx23",
                "description": "Hetzner Cloud server-type name; availability is provider-defined."
            },
            "image": {
                "type": "string",
                "pattern": "^(ubuntu|debian)-",
                "default": "ubuntu-24.04"
            },
            "location": { "type": ["string", "null"] },
            "ssh_keys": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "minItems": 1,
                "description": "At least one Hetzner SSH key name or ID is required."
            },
            "ssh_user": {
                "type": "string",
                "default": "root"
            },
            "identity_file": {
                "type": ["string", "null"],
                "description": "Absolute path on the local machine; never transferred."
            },
            "allowed_ssh_cidrs": {
                "type": "array",
                "items": { "type": "string" },
                "minItems": 1,
                "description": "Required source CIDRs for TCP port 22. /0 is rejected."
            },
            "bootstrap": {
                "enum": ["install", "cloud-init", "verify"],
                "default": "install"
            }
        },
        "required": ["ssh_keys", "allowed_ssh_cidrs"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lightrail_plugin_protocol::OperationContext;

    #[test]
    fn cidrs_require_explicit_non_global_networks() {
        assert!(validate_cidrs(&[]).is_err());
        assert!(validate_cidrs(&["0.0.0.0/0".to_owned()]).is_err());
        assert!(validate_cidrs(&["::/0".to_owned()]).is_err());
        assert!(validate_cidrs(&["203.0.113.4/32".to_owned()]).is_ok());
        assert!(validate_cidrs(&["2001:db8::/64".to_owned()]).is_ok());
        assert!(validate_cidrs(&["203.0.113.4/33".to_owned()]).is_err());
        assert!(validate_cidrs(&["203.0.113.4/24".to_owned()]).is_err());
        assert!(validate_cidrs(&["203.0.113.0/24".to_owned()]).is_ok());
    }

    #[test]
    fn identity_is_deterministic_and_label_selector_is_immutable() {
        let context = OperationContext {
            environment_id: "project:preview:feature/login".to_owned(),
            metadata: json!({
                "project_id": "018f6a1c-immutable",
                "project_slug": "My Amazing Project"
            }),
            ..OperationContext::default()
        };
        let first = ResourceIdentity::from_context(&context).unwrap();
        let second = ResourceIdentity::from_context(&context).unwrap();
        assert_eq!(first, second);
        assert!(first.server_name.starts_with("lr-my-amazing-project-"));
        assert!(first.server_name.len() <= 58);
        assert!(first.firewall_name.len() <= 61);
        assert!(
            first
                .environment_selector()
                .contains("lightrail-project=p-")
        );
        assert!(!first.environment_selector().contains("feature/login"));
    }

    #[test]
    fn token_is_not_part_of_serialized_settings_or_fingerprints() {
        let settings = Settings {
            allowed_ssh_cidrs: vec!["203.0.113.4/32".to_owned()],
            ..Settings::default()
        };
        let encoded = serde_json::to_string(&settings).unwrap();
        assert!(!encoded.contains("actual-provider-token"));
        assert_eq!(settings.config_fingerprint().len(), 64);
    }
}
