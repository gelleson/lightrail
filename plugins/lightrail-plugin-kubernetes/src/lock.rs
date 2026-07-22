use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use lightrail_plugin_protocol::{
    ErrorKind, LockAcquireRequest, LockAcquireResult, LockReleaseRequest, LockReleaseResult,
    LockScope, PluginError, PluginResult, SecretValue,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{sync::Mutex, task::JoinHandle, time::sleep};
use uuid::Uuid;

use crate::{
    command::{CancellationRegistry, kubectl, kubectl_json},
    config::Settings,
    model::{MANAGED_LABEL, short_hash},
};

const DEFAULT_LEASE_SECONDS: u64 = 60;
const MIN_LEASE_SECONDS: u64 = 30;
const MAX_LEASE_SECONDS: u64 = 300;
const TOKEN_HASH_ANNOTATION: &str = "lightrail.dev/lock-token-sha256";
const EXPIRES_ANNOTATION: &str = "lightrail.dev/lock-expires-at-unix";
const SCOPE_ANNOTATION: &str = "lightrail.dev/lock-scope-id";

pub(crate) struct LeaseLocks {
    locks: Arc<Mutex<HashMap<String, HeldLock>>>,
    cancellations: CancellationRegistry,
}

struct HeldLock {
    request: LockIdentity,
    token: String,
    token_hash: String,
    lease_name: String,
    lease_seconds: u64,
    releasing: bool,
    lost: Arc<AtomicBool>,
    heartbeat: JoinHandle<()>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LockIdentity {
    environment_id: String,
    scope: LockScope,
    scope_id: String,
    operation_id: String,
}

impl Default for LeaseLocks {
    fn default() -> Self {
        Self::new(CancellationRegistry::default())
    }
}

impl LeaseLocks {
    pub(crate) fn new(cancellations: CancellationRegistry) -> Self {
        Self {
            locks: Arc::new(Mutex::new(HashMap::new())),
            cancellations,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn acquire(
        &self,
        settings: &Settings,
        request: LockAcquireRequest,
    ) -> PluginResult<LockAcquireResult> {
        validate_request(&request)?;
        let identity = LockIdentity {
            environment_id: request.environment_id.clone(),
            scope: request.scope,
            scope_id: request.scope_id.clone(),
            operation_id: request.operation_id.clone(),
        };
        let owner_key = owner_key(&identity);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(request.timeout_ms))
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Validation,
                    "lock_timeout_too_large",
                    "Kubernetes Lease lock timeout is too large",
                )
            })?;
        if let Some(existing) = self
            .reacquire(settings, &owner_key, &identity, deadline)
            .await?
        {
            return Ok(existing);
        }

        let lease_seconds = request
            .lease_ms
            .map_or(DEFAULT_LEASE_SECONDS, |milliseconds| {
                milliseconds.div_ceil(1000)
            })
            .clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS);
        let lease_name = lease_name(&request.scope_id);
        let token = Uuid::new_v4().to_string();
        let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

        loop {
            let Some(command_deadline) = remaining_command_timeout(settings, deadline) else {
                return Ok(not_acquired(
                    "timed out waiting for the Kubernetes project Lease",
                ));
            };
            let now = unix_now()?;
            let expiry = now.saturating_add(lease_seconds);
            let manifest = lease_manifest(
                &settings.control_namespace,
                &lease_name,
                &identity,
                &token_hash,
                expiry,
                lease_seconds,
                None,
            );
            let create = kubectl(
                settings,
                &["create".to_owned(), "-f".to_owned(), "-".to_owned()],
                Some(serde_json::to_vec(&manifest).map_err(serialization_error)?),
                command_deadline,
                None,
            )
            .await;
            match create {
                Ok(_) => {
                    return self
                        .remember(
                            settings.clone(),
                            owner_key,
                            identity,
                            token,
                            token_hash,
                            lease_name,
                            lease_seconds,
                        )
                        .await;
                }
                Err(error) if error.kind == ErrorKind::Conflict => {}
                Err(error) => return Err(error),
            }

            let Some(command_deadline) = remaining_command_timeout(settings, deadline) else {
                return Ok(not_acquired(
                    "timed out waiting for the Kubernetes project Lease",
                ));
            };
            let Some(current) =
                get_lease_with_timeout(settings, &lease_name, command_deadline).await?
            else {
                if Instant::now() >= deadline {
                    return Ok(not_acquired(
                        "the Kubernetes Lease changed during acquisition",
                    ));
                }
                sleep_until_deadline(deadline, Duration::from_millis(100)).await;
                continue;
            };
            if !lease_matches_scope(&current, &identity.scope_id) {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "lease_scope_mismatch",
                    "Kubernetes Lease name is occupied by an object outside the exact project lock scope",
                ));
            }
            let current_expiry = lease_expiry(&current).ok_or_else(malformed_lease_error)?;
            if lease_holder(&current).is_none() || lease_token_hash(&current).is_none() {
                return Err(malformed_lease_error());
            }
            if lease_holder(&current) == Some(identity.operation_id.as_str()) {
                return Ok(not_acquired(
                    "the operation Lease is held by another plugin process for the same operation",
                ));
            }
            if current_expiry > now {
                if Instant::now() >= deadline {
                    return Ok(not_acquired(
                        lease_holder(&current).unwrap_or("another Kubernetes operation"),
                    ));
                }
                sleep_until_deadline(deadline, Duration::from_millis(250)).await;
                continue;
            }
            let resource_version = current
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    PluginError::permanent(
                        ErrorKind::Internal,
                        "lease_resource_version_missing",
                        "Kubernetes Lease did not contain metadata.resourceVersion",
                    )
                })?;
            let replacement = lease_manifest(
                &settings.control_namespace,
                &lease_name,
                &identity,
                &token_hash,
                expiry,
                lease_seconds,
                Some(resource_version),
            );
            let Some(command_deadline) = remaining_command_timeout(settings, deadline) else {
                return Ok(not_acquired(
                    "timed out waiting for the Kubernetes project Lease",
                ));
            };
            let replace = kubectl(
                settings,
                &["replace".to_owned(), "-f".to_owned(), "-".to_owned()],
                Some(serde_json::to_vec(&replacement).map_err(serialization_error)?),
                command_deadline,
                None,
            )
            .await;
            match replace {
                Ok(_) => {
                    return self
                        .remember(
                            settings.clone(),
                            owner_key,
                            identity,
                            token,
                            token_hash,
                            lease_name,
                            lease_seconds,
                        )
                        .await;
                }
                Err(error) if matches!(error.kind, ErrorKind::Conflict) => {
                    if Instant::now() >= deadline {
                        return Ok(not_acquired(
                            "another operation renewed the Kubernetes Lease",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn reacquire(
        &self,
        settings: &Settings,
        owner_key: &str,
        identity: &LockIdentity,
        deadline: Instant,
    ) -> PluginResult<Option<LockAcquireResult>> {
        let existing = {
            let locks = self.locks.lock().await;
            locks.get(owner_key).map(|lock| {
                (
                    lock.request.clone(),
                    lock.token.clone(),
                    lock.token_hash.clone(),
                    lock.lease_name.clone(),
                    lock.releasing,
                    Arc::clone(&lock.lost),
                )
            })
        };
        let Some((request, token, token_hash, lease_name, releasing, lost)) = existing else {
            return Ok(None);
        };
        if request != *identity || releasing || lost.load(Ordering::Acquire) {
            return Ok(Some(not_acquired(
                "the previously held Kubernetes Lease lost authority",
            )));
        }
        let Some(command_deadline) = remaining_command_timeout(settings, deadline) else {
            return Ok(Some(not_acquired(
                "timed out reasserting the Kubernetes project Lease",
            )));
        };
        let current = get_lease_with_timeout(settings, &lease_name, command_deadline).await?;
        if current.as_ref().is_some_and(|lease| {
            lease_matches_scope(lease, &identity.scope_id)
                && lease_holder(lease) == Some(identity.operation_id.as_str())
                && lease_token_hash(lease) == Some(token_hash.as_str())
                && lease_expiry(lease)
                    .is_some_and(|expiry| unix_now().is_ok_and(|now| expiry > now))
        }) {
            Ok(Some(LockAcquireResult {
                acquired: true,
                token: Some(SecretValue::new(token)),
                expires_at: None,
                holder: None,
            }))
        } else {
            lost.store(true, Ordering::Release);
            Ok(Some(not_acquired(
                "the previously held Kubernetes Lease is no longer authoritative",
            )))
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn remember(
        &self,
        settings: Settings,
        owner_key: String,
        identity: LockIdentity,
        token: String,
        token_hash: String,
        lease_name: String,
        lease_seconds: u64,
    ) -> PluginResult<LockAcquireResult> {
        let lost = Arc::new(AtomicBool::new(false));
        let heartbeat = tokio::spawn(heartbeat(
            settings,
            identity.clone(),
            lease_name.clone(),
            token_hash.clone(),
            lease_seconds,
            Arc::clone(&lost),
            self.cancellations.clone(),
        ));
        let mut locks = self.locks.lock().await;
        if let Some(previous) = locks.insert(
            owner_key,
            HeldLock {
                request: identity,
                token: token.clone(),
                token_hash,
                lease_name,
                lease_seconds,
                releasing: false,
                lost,
                heartbeat,
            },
        ) {
            previous.heartbeat.abort();
        }
        Ok(LockAcquireResult {
            acquired: true,
            token: Some(SecretValue::new(token)),
            expires_at: None,
            holder: None,
        })
    }

    pub(crate) async fn release(
        &self,
        settings: &Settings,
        request: LockReleaseRequest,
    ) -> PluginResult<LockReleaseResult> {
        let token = request.token.expose_secret();
        let key = {
            let locks = self.locks.lock().await;
            locks
                .iter()
                .find_map(|(key, lock)| (lock.token == token).then(|| key.clone()))
        };
        let Some(key) = key else {
            return Ok(LockReleaseResult { released: true });
        };
        let (identity, token_hash, lease_name) = {
            let mut locks = self.locks.lock().await;
            let lock = locks.get_mut(&key).ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Conflict,
                    "lock_owner_missing",
                    "Kubernetes Lease lock disappeared before release",
                )
            })?;
            if lock.request.environment_id != request.environment_id
                || lock.request.scope != request.scope
                || lock.request.scope_id != request.scope_id
                || lock.request.operation_id != request.operation_id
            {
                return Err(PluginError::permanent(
                    ErrorKind::Conflict,
                    "lock_owner_mismatch",
                    "Kubernetes Lease token does not belong to this lock owner",
                ));
            }
            lock.releasing = true;
            lock.heartbeat.abort();
            (
                lock.request.clone(),
                lock.token_hash.clone(),
                lock.lease_name.clone(),
            )
        };
        let current = get_lease(settings, &lease_name).await?;
        let current =
            match authoritative_lease_for_release(current.as_ref(), &identity, token_hash.as_str())
            {
                Ok(current) => current,
                Err(error) => {
                    self.locks.lock().await.remove(&key);
                    return Err(error);
                }
            };
        let resource_version = current
            .pointer("/metadata/resourceVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PluginError::permanent(
                    ErrorKind::Internal,
                    "lease_resource_version_missing",
                    "Kubernetes Lease did not contain metadata.resourceVersion",
                )
            })?;
        let released = released_lease_manifest(
            &settings.control_namespace,
            &lease_name,
            &identity,
            &token_hash,
            resource_version,
        );
        kubectl(
            settings,
            &["replace".to_owned(), "-f".to_owned(), "-".to_owned()],
            Some(serde_json::to_vec(&released).map_err(serialization_error)?),
            settings.command_timeout(),
            None,
        )
        .await?;
        self.locks.lock().await.remove(&key);
        Ok(LockReleaseResult { released: true })
    }

    pub(crate) async fn assert_authority(
        &self,
        settings: &Settings,
        operation_id: &str,
    ) -> PluginResult<()> {
        let held = {
            let locks = self.locks.lock().await;
            locks.values().find_map(|lock| {
                (lock.request.operation_id == operation_id).then(|| {
                    (
                        lock.request.clone(),
                        lock.token_hash.clone(),
                        lock.lease_name.clone(),
                        lock.lease_seconds,
                        lock.releasing,
                        Arc::clone(&lock.lost),
                    )
                })
            })
        }
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::LockUnavailable,
                "lease_not_held",
                "the Kubernetes mutation no longer has a locally held project Lease",
            )
        })?;
        let (identity, token_hash, lease_name, lease_seconds, releasing, lost) = held;
        if releasing || lost.load(Ordering::Acquire) {
            return Err(lock_lost_error());
        }
        let deadline = heartbeat_timeout(settings, lease_seconds);
        let current = get_lease_with_timeout(settings, &lease_name, deadline)
            .await?
            .ok_or_else(lock_lost_error)?;
        let now = unix_now()?;
        if !lease_matches_scope(&current, &identity.scope_id)
            || lease_holder(&current) != Some(identity.operation_id.as_str())
            || lease_token_hash(&current) != Some(token_hash.as_str())
            || lease_expiry(&current).is_none_or(|expiry| expiry <= now)
        {
            lost.store(true, Ordering::Release);
            return Err(lock_lost_error());
        }
        Ok(())
    }
}

async fn heartbeat(
    settings: Settings,
    identity: LockIdentity,
    lease_name: String,
    token_hash: String,
    lease_seconds: u64,
    lost: Arc<AtomicBool>,
    cancellations: CancellationRegistry,
) {
    let interval = Duration::from_secs((lease_seconds / 3).max(5));
    loop {
        sleep(interval).await;
        let result = renew(
            &settings,
            &identity,
            &lease_name,
            &token_hash,
            lease_seconds,
        )
        .await;
        if result.is_err() {
            lost.store(true, Ordering::Release);
            cancellations.cancel(&identity.operation_id);
            break;
        }
    }
}

async fn renew(
    settings: &Settings,
    identity: &LockIdentity,
    lease_name: &str,
    token_hash: &str,
    lease_seconds: u64,
) -> PluginResult<()> {
    let request_timeout = heartbeat_timeout(settings, lease_seconds);
    let current = get_lease_with_timeout(settings, lease_name, request_timeout)
        .await?
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::LockUnavailable,
                "lease_disappeared",
                "authoritative Kubernetes Lease disappeared",
            )
        })?;
    if !lease_matches_scope(&current, &identity.scope_id)
        || lease_holder(&current) != Some(identity.operation_id.as_str())
        || lease_token_hash(&current) != Some(token_hash)
    {
        return Err(PluginError::permanent(
            ErrorKind::LockUnavailable,
            "lease_authority_lost",
            "authoritative Kubernetes Lease changed owner",
        ));
    }
    let resource_version = current
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            PluginError::permanent(
                ErrorKind::Internal,
                "lease_resource_version_missing",
                "Kubernetes Lease did not contain metadata.resourceVersion",
            )
        })?;
    let expiry = unix_now()?.saturating_add(lease_seconds);
    let replacement = lease_manifest(
        &settings.control_namespace,
        lease_name,
        identity,
        token_hash,
        expiry,
        lease_seconds,
        Some(resource_version),
    );
    kubectl(
        settings,
        &["replace".to_owned(), "-f".to_owned(), "-".to_owned()],
        Some(serde_json::to_vec(&replacement).map_err(serialization_error)?),
        request_timeout,
        None,
    )
    .await?;
    Ok(())
}

async fn get_lease(settings: &Settings, name: &str) -> PluginResult<Option<Value>> {
    get_lease_with_timeout(settings, name, settings.command_timeout()).await
}

async fn get_lease_with_timeout(
    settings: &Settings,
    name: &str,
    deadline: Duration,
) -> PluginResult<Option<Value>> {
    let result = kubectl_json(
        settings,
        &[
            "get".to_owned(),
            "lease".to_owned(),
            name.to_owned(),
            "--namespace".to_owned(),
            settings.control_namespace.clone(),
            "-o".to_owned(),
            "json".to_owned(),
        ],
        deadline,
    )
    .await;
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn released_lease_manifest(
    namespace: &str,
    name: &str,
    identity: &LockIdentity,
    token_hash: &str,
    resource_version: &str,
) -> Value {
    let mut released = lease_manifest(
        namespace,
        name,
        identity,
        token_hash,
        0,
        DEFAULT_LEASE_SECONDS,
        Some(resource_version),
    );
    released["spec"]["holderIdentity"] = Value::String(String::new());
    released
}

fn authoritative_lease_for_release<'a>(
    current: Option<&'a Value>,
    identity: &LockIdentity,
    token_hash: &str,
) -> PluginResult<&'a Value> {
    let current = current.ok_or_else(|| {
        PluginError::permanent(
            ErrorKind::Conflict,
            "lock_authority_lost",
            "authoritative Kubernetes Lease disappeared before release",
        )
    })?;
    if !lease_matches_scope(current, &identity.scope_id)
        || lease_holder(current) != Some(identity.operation_id.as_str())
        || lease_token_hash(current) != Some(token_hash)
    {
        return Err(PluginError::permanent(
            ErrorKind::Conflict,
            "lock_authority_lost",
            "Kubernetes Lease changed before release; it was not relinquished",
        ));
    }
    Ok(current)
}

#[allow(clippy::too_many_arguments)]
fn lease_manifest(
    namespace: &str,
    name: &str,
    identity: &LockIdentity,
    token_hash: &str,
    expiry: u64,
    lease_seconds: u64,
    resource_version: Option<&str>,
) -> Value {
    let mut metadata = json!({
        "name": name,
        "namespace": namespace,
        "labels": {MANAGED_LABEL: "lightrail"},
        "annotations": {
            TOKEN_HASH_ANNOTATION: token_hash,
            EXPIRES_ANNOTATION: expiry.to_string(),
            SCOPE_ANNOTATION: identity.scope_id,
        }
    });
    if let Some(resource_version) = resource_version {
        metadata["resourceVersion"] = Value::String(resource_version.to_owned());
    }
    json!({
        "apiVersion": "coordination.k8s.io/v1",
        "kind": "Lease",
        "metadata": metadata,
        "spec": {
            "holderIdentity": identity.operation_id,
            "leaseDurationSeconds": lease_seconds,
        }
    })
}

fn lease_holder(lease: &Value) -> Option<&str> {
    lease
        .pointer("/spec/holderIdentity")
        .and_then(Value::as_str)
}

fn lease_token_hash(lease: &Value) -> Option<&str> {
    lease
        .pointer("/metadata/annotations/lightrail.dev~1lock-token-sha256")
        .and_then(Value::as_str)
}

fn lease_expiry(lease: &Value) -> Option<u64> {
    lease
        .pointer("/metadata/annotations/lightrail.dev~1lock-expires-at-unix")
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
}

fn lease_matches_scope(lease: &Value, scope_id: &str) -> bool {
    lease
        .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
        .and_then(Value::as_str)
        == Some("lightrail")
        && lease
            .pointer("/metadata/annotations/lightrail.dev~1lock-scope-id")
            .and_then(Value::as_str)
            == Some(scope_id)
}

fn owner_key(identity: &LockIdentity) -> String {
    format!(
        "{:?}|{}|{}",
        identity.scope, identity.scope_id, identity.operation_id
    )
}

fn lease_name(scope_id: &str) -> String {
    format!("lr-lock-{}", short_hash(scope_id, 32))
}

fn validate_request(request: &LockAcquireRequest) -> PluginResult<()> {
    if request.scope_id.trim().is_empty() || request.operation_id.trim().is_empty() {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "lock_identity_required",
            "Kubernetes Lease lock requires non-empty scope_id and operation_id",
        ));
    }
    if request.timeout_ms == 0 {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "lock_timeout_required",
            "Kubernetes Lease lock timeout must be greater than zero",
        ));
    }
    if request.scope != LockScope::Project {
        return Err(PluginError::permanent(
            ErrorKind::Validation,
            "kubernetes_project_lock_required",
            "Kubernetes environment mutations require the project-wide Lease scope",
        ));
    }
    Ok(())
}

fn remaining_command_timeout(settings: &Settings, deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    if remaining.is_zero() {
        return None;
    }
    Some(settings.command_timeout().min(remaining))
}

async fn sleep_until_deadline(deadline: Instant, requested: Duration) {
    if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        sleep(requested.min(remaining)).await;
    }
}

fn heartbeat_timeout(settings: &Settings, lease_seconds: u64) -> Duration {
    settings
        .command_timeout()
        .min(Duration::from_secs((lease_seconds / 6).clamp(1, 10)))
}

fn lock_lost_error() -> PluginError {
    PluginError::permanent(
        ErrorKind::LockUnavailable,
        "lease_authority_lost",
        "authoritative Kubernetes project Lease was lost",
    )
}

fn malformed_lease_error() -> PluginError {
    PluginError::permanent(
        ErrorKind::Conflict,
        "lease_metadata_invalid",
        "Kubernetes project Lease is missing authoritative ownership or expiry metadata",
    )
}

fn not_acquired(holder: impl Into<String>) -> LockAcquireResult {
    LockAcquireResult {
        acquired: false,
        token: None,
        expires_at: None,
        holder: Some(holder.into()),
    }
}

fn unix_now() -> PluginResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            PluginError::permanent(
                ErrorKind::Internal,
                "system_clock_before_epoch",
                format!("system clock cannot maintain a Kubernetes Lease: {error}"),
            )
        })
}

fn serialization_error(error: impl std::fmt::Display) -> PluginError {
    PluginError::permanent(
        ErrorKind::Internal,
        "lease_serialization_failed",
        format!("failed to serialize Kubernetes Lease: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> LockIdentity {
        LockIdentity {
            environment_id: "lr-env".to_owned(),
            scope: LockScope::Project,
            scope_id: "project:test".to_owned(),
            operation_id: "operation-1".to_owned(),
        }
    }

    #[test]
    fn lease_persists_only_a_token_digest() {
        let manifest = lease_manifest(
            "lightrail-system",
            "lr-lock-test",
            &identity(),
            "digest-only",
            100,
            60,
            None,
        );
        assert_eq!(lease_token_hash(&manifest), Some("digest-only"));
        assert!(lease_matches_scope(&manifest, "project:test"));
        assert!(!lease_matches_scope(&manifest, "project:other"));
        assert!(!manifest.to_string().contains("plaintext-token"));
    }

    #[test]
    fn replacement_carries_resource_version() {
        let manifest = lease_manifest(
            "lightrail-system",
            "lr-lock-test",
            &identity(),
            "digest",
            100,
            60,
            Some("42"),
        );
        assert_eq!(manifest["metadata"]["resourceVersion"], "42");
    }

    #[test]
    fn release_retains_vacant_lease_with_exact_resource_version() {
        let manifest = released_lease_manifest(
            "lightrail-system",
            "lr-lock-test",
            &identity(),
            "digest",
            "42",
        );
        assert_eq!(manifest["metadata"]["resourceVersion"], "42");
        assert_eq!(manifest["spec"]["holderIdentity"], "");
        assert_eq!(manifest["metadata"]["annotations"][EXPIRES_ANNOTATION], "0");
    }

    #[test]
    fn release_fails_when_a_locally_held_authoritative_lease_disappears() {
        let error = authoritative_lease_for_release(None, &identity(), "digest")
            .expect_err("missing authoritative Lease must not look released");
        assert_eq!(error.code, "lock_authority_lost");

        let changed = lease_manifest(
            "lightrail-system",
            "lr-lock-test",
            &identity(),
            "other-digest",
            100,
            60,
            Some("42"),
        );
        assert_eq!(
            authoritative_lease_for_release(Some(&changed), &identity(), "digest")
                .expect_err("changed token digest")
                .code,
            "lock_authority_lost"
        );
    }

    #[test]
    fn only_project_scope_is_accepted() {
        let request = LockAcquireRequest {
            environment_id: "lr-env".to_owned(),
            scope: LockScope::Environment,
            scope_id: "environment:lr-env".to_owned(),
            operation_id: "operation-1".to_owned(),
            timeout_ms: 1,
            lease_ms: None,
        };
        assert_eq!(
            validate_request(&request)
                .expect_err("environment scope must fail")
                .code,
            "kubernetes_project_lock_required"
        );
    }

    #[test]
    fn heartbeat_command_timeout_is_shorter_than_the_lease() {
        let settings = Settings {
            command_timeout_seconds: 300,
            ..Settings::default()
        };
        assert!(heartbeat_timeout(&settings, 30) < Duration::from_secs(30));
    }

    #[test]
    fn project_scope_serializes_every_environment_on_one_lease() {
        let first = LockIdentity {
            environment_id: "lr-feature-a".to_owned(),
            scope: LockScope::Project,
            scope_id: "project:6d840d39-1b41-4c8d-9cc4-23ba6539135d".to_owned(),
            operation_id: "operation-a".to_owned(),
        };
        let second = LockIdentity {
            environment_id: "lr-feature-b".to_owned(),
            scope: LockScope::Project,
            scope_id: first.scope_id.clone(),
            operation_id: "operation-b".to_owned(),
        };
        assert_eq!(lease_name(&first.scope_id), lease_name(&second.scope_id));
        assert_ne!(owner_key(&first), owner_key(&second));
    }
}
