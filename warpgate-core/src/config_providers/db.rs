use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use data_encoding::BASE64;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use tracing::*;
use uuid::Uuid;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Target, User, UserAuthCredential, UserPasswordCredential, UserPublicKeyCredential,
    UserRequireCredentialsPolicy, UserSsoCredential, UserTotpCredential, WarpgateError,
};
use warpgate_db_entities as entities;
use warpgate_sso::SsoProviderConfig;

use super::ConfigProvider;

pub struct DatabaseConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
}

impl DatabaseConfigProvider {
    pub async fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Self {
        Self { db: db.clone() }
    }

    async fn maybe_autocreate_sso_user(
        &self,
        db: &DatabaseConnection,
        credential: UserSsoCredential,
        preferred_username: String,
    ) -> Result<Option<String>, WarpgateError> {
        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(preferred_username.clone()),
            description: Set("".into()),
            credential_policy: Set(serde_json::to_value(
                UserRequireCredentialsPolicy::default(),
            )?),
            rate_limit_bytes_per_second: Set(None),
        }
        .insert(db)
        .await?;

        entities::SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            ..entities::SsoCredential::ActiveModel::from(credential)
        }
        .insert(db)
        .await?;

        Ok(Some(preferred_username))
    }
}

impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<User>, WarpgateError> {
        let db = self.db.lock().await;

        let users = entities::User::Entity::find()
            .order_by_asc(entities::User::Column::Username)
            .all(&*db)
            .await?;

        let users: Result<Vec<User>, _> = users.into_iter().map(|t| t.try_into()).collect();

        users
    }

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError> {
        let db = self.db.lock().await;

        let targets = entities::Target::Entity::find()
            .order_by_asc(entities::Target::Column::Name)
            .all(&*db)
            .await?;

        let targets: Result<Vec<Target>, _> = targets.into_iter().map(|t| t.try_into()).collect();

        Ok(targets?)
    }

    async fn get_credential_policy(
        &mut self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let user = user_model.load_details(&db).await?;

        let mut available_credential_types = user
            .credentials
            .iter()
            .map(|x| x.kind())
            .collect::<HashSet<_>>();
        available_credential_types.insert(CredentialKind::WebUserApproval);

        let supported_credential_types = supported_credential_types
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .intersection(&available_credential_types)
            .copied()
            .collect::<HashSet<_>>();

        // "Any single credential" policy should not include WebUserApproval
        // if other authentication methods are available because it could lead to user confusion
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: if supported_credential_types.len() > 1 {
                supported_credential_types
                    .iter()
                    .cloned()
                    .filter(|x| x != &CredentialKind::WebUserApproval)
                    .collect()
            } else {
                supported_credential_types.clone()
            },
        }) as Box<dyn CredentialPolicy + Sync + Send>;

        if let Some(req) = user.credential_policy.clone() {
            let mut policy = PerProtocolCredentialPolicy {
                default: default_policy,
                protocols: HashMap::new(),
            };

            if let Some(p) = req.http {
                policy.protocols.insert(
                    "HTTP",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.mysql {
                policy.protocols.insert(
                    "MySQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.postgres {
                policy.protocols.insert(
                    "PostgreSQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.ssh {
                policy.protocols.insert(
                    "SSH",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types,
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }

            Ok(Some(
                Box::new(policy) as Box<dyn CredentialPolicy + Sync + Send>
            ))
        } else {
            Ok(Some(default_policy))
        }
    }

    async fn username_for_sso_credential(
        &mut self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError> {
        let db = self.db.lock().await;

        let AuthCredential::Sso {
            provider: client_provider,
            email: client_email,
        } = client_credential
        else {
            return Ok(None);
        };

        let cred = entities::SsoCredential::Entity::find()
            .filter(
                entities::SsoCredential::Column::Email.eq(client_email).and(
                    entities::SsoCredential::Column::Provider
                        .eq(client_provider)
                        .or(entities::SsoCredential::Column::Provider.is_null()),
                ),
            )
            .one(&*db)
            .await?;

        if let Some(cred) = cred {
            let user = cred.find_related(entities::User::Entity).one(&*db).await?;

            if let Some(user) = user {
                return Ok(Some(user.username.clone()));
            }
        }

        if sso_config.auto_create_users {
            let Some(preferred_username) = preferred_username else {
                error!("The OIDC server did not provide a preferred_username claim for this user");
                return Ok(None);
            };
            return self
                .maybe_autocreate_sso_user(
                    &db,
                    UserSsoCredential {
                        email: client_email.clone(),
                        provider: Some(client_provider.clone()),
                    },
                    preferred_username,
                )
                .await;
        }

        Ok(None)
    }

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let user_details = user_model.load_details(&db).await?;

        match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let base64_bytes = BASE64.encode(public_key_bytes);
                let openssh_public_key = format!("{kind} {base64_bytes}");
                debug!(
                    username = &user_details.username[..],
                    "Client key: {}", openssh_public_key
                );

                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::PublicKey(UserPublicKeyCredential {
                            key: ref user_key,
                        }) => &openssh_public_key == user_key.expose_secret(),
                        _ => false,
                    }))
            }
            AuthCredential::Password(client_password) => {
                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Password(UserPasswordCredential {
                            hash: ref user_password_hash,
                        }) => verify_password_hash(
                            client_password.expose_secret(),
                            user_password_hash.expose_secret(),
                        )
                        .unwrap_or_else(|e| {
                            error!(
                                username = &user_details.username[..],
                                "Error verifying password hash: {}", e
                            );
                            false
                        }),
                        _ => false,
                    }))
            }
            AuthCredential::Otp(client_otp) => {
                Ok(user_details
                    .credentials
                    .iter()
                    .any(|credential| match credential {
                        UserAuthCredential::Totp(UserTotpCredential {
                            key: ref user_otp_key,
                        }) => verify_totp(client_otp.expose_secret(), user_otp_key),
                        _ => false,
                    }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                for credential in user_details.credentials.iter() {
                    if let UserAuthCredential::Sso(UserSsoCredential {
                        ref provider,
                        ref email,
                    }) = credential
                    {
                        if provider.as_ref().unwrap_or(client_provider) == client_provider
                            && email == client_email
                        {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            _ => Err(WarpgateError::InvalidCredentialType),
        }
    }

    async fn authorize_target(
        &mut self,
        username: &str,
        target_name: &str,
    ) -> Result<super::TargetAuthResult, WarpgateError> {
        let db = self.db.lock().await;
        let now = Utc::now();

        let target_model = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(super::TargetAuthResult {
                allowed: false,
                denial_reason: Some("user not found".to_string()),
            });
        };

        let Some(target_model) = target_model else {
            warn!("Selected target not found: {}", target_name);
            return Ok(super::TargetAuthResult {
                allowed: false,
                denial_reason: Some("target not found".to_string()),
            });
        };

        // Get user's role assignments (including expired ones to check for expiration)
        let user_role_assignments = entities::UserRoleAssignment::Entity::find()
            .filter(entities::UserRoleAssignment::Column::UserId.eq(user_model.id))
            .all(&*db)
            .await?;

        // Check if user has any role assignments at all
        if user_role_assignments.is_empty() {
            return Ok(super::TargetAuthResult {
                allowed: false,
                denial_reason: Some("no role assignments for user".to_string()),
            });
        }

        // Separate valid and expired user role assignments
        let mut valid_user_role_ids: HashSet<uuid::Uuid> = HashSet::new();
        let mut has_expired_user_roles = false;

        for assignment in &user_role_assignments {
            let is_valid = assignment.expires_at.map(|exp| exp > now).unwrap_or(true);
            if is_valid {
                valid_user_role_ids.insert(assignment.role_id);
            } else {
                has_expired_user_roles = true;
            }
        }

        if valid_user_role_ids.is_empty() {
            return Ok(super::TargetAuthResult {
                allowed: false,
                denial_reason: Some("all user role assignments have expired".to_string()),
            });
        }

        // Get target's role assignments (including expired ones)
        let target_role_assignments = entities::TargetRoleAssignment::Entity::find()
            .filter(entities::TargetRoleAssignment::Column::TargetId.eq(target_model.id))
            .all(&*db)
            .await?;

        // Check if user has valid access to target via direct assignment
        let mut has_expired_target_access = false;
        for assignment in &target_role_assignments {
            if valid_user_role_ids.contains(&assignment.role_id) {
                let is_valid = assignment.expires_at.map(|exp| exp > now).unwrap_or(true);
                if is_valid {
                    return Ok(super::TargetAuthResult {
                        allowed: true,
                        denial_reason: None,
                    });
                } else {
                    has_expired_target_access = true;
                }
            }
        }

        // Check group-based access if target belongs to a group
        if let Some(group_id) = target_model.group_id {
            let group_role_assignments = entities::TargetGroupRoleAssignment::Entity::find()
                .filter(entities::TargetGroupRoleAssignment::Column::TargetGroupId.eq(group_id))
                .all(&*db)
                .await?;

            let group_role_ids: HashSet<uuid::Uuid> = group_role_assignments
                .into_iter()
                .map(|assignment| assignment.role_id)
                .collect();

            let group_access = valid_user_role_ids.intersection(&group_role_ids).count() > 0;

            if group_access {
                return Ok(super::TargetAuthResult {
                    allowed: true,
                    denial_reason: None,
                });
            }
        }

        // Determine the most specific denial reason
        let denial_reason = if has_expired_target_access {
            "target access has expired".to_string()
        } else if has_expired_user_roles {
            "no valid role grants access to this target".to_string()
        } else {
            "no role grants access to this target".to_string()
        };

        Ok(super::TargetAuthResult {
            allowed: false,
            denial_reason: Some(denial_reason),
        })
    }

    async fn authorize_file_transfer(
        &mut self,
        username: &str,
        target_name: &str,
        target_allows_sftp: bool,
    ) -> Result<super::FileTransferAuthResult, WarpgateError> {
        let db = self.db.lock().await;
        let now = Utc::now();

        let target_model = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("User not found for file transfer check: {}", username);
            return Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("user not found".to_string()),
            });
        };

        let Some(target_model) = target_model else {
            warn!("Target not found for file transfer check: {}", target_name);
            return Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("target not found".to_string()),
            });
        };

        // Get user's valid (non-expired) role assignments
        let user_role_assignments = entities::UserRoleAssignment::Entity::find()
            .filter(entities::UserRoleAssignment::Column::UserId.eq(user_model.id))
            .all(&*db)
            .await?;

        // Filter to valid (non-expired) assignments and check user-role level file transfer permissions
        let mut user_role_has_allow = false;
        let mut user_role_has_deny = false;
        let mut valid_user_role_ids: HashSet<uuid::Uuid> = HashSet::new();

        for assignment in &user_role_assignments {
            let is_valid = assignment.expires_at.map(|exp| exp > now).unwrap_or(true);
            if is_valid {
                valid_user_role_ids.insert(assignment.role_id);
                // Check user-role level file transfer permission
                match assignment.allow_file_transfer.as_deref() {
                    Some("deny") => user_role_has_deny = true,
                    Some("allow") => user_role_has_allow = true,
                    _ => {} // null means allow by default at user-role level
                }
            }
        }

        if valid_user_role_ids.is_empty() {
            return Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("no valid role assignments".to_string()),
            });
        }

        // User-role level deny takes highest priority
        if user_role_has_deny {
            info!(
                username,
                target = target_name,
                "File transfer denied by user-role assignment"
            );
            return Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("denied by user-role assignment (SFTP disabled for user's role)".to_string()),
            });
        }

        // Get target role assignments for this target and user's roles
        let target_role_assignments = entities::TargetRoleAssignment::Entity::find()
            .filter(entities::TargetRoleAssignment::Column::TargetId.eq(target_model.id))
            .all(&*db)
            .await?;

        // Check for target-role level file transfer overrides
        // Priority: deny > allow > inherit from target
        let mut target_role_has_allow = false;
        let mut target_role_has_deny = false;

        for assignment in target_role_assignments {
            // Only consider valid (non-expired) assignments for user's roles
            let is_valid = assignment.expires_at.map(|exp| exp > now).unwrap_or(true);
            let is_user_role = valid_user_role_ids.contains(&assignment.role_id);

            if is_valid && is_user_role {
                match assignment.allow_file_transfer.as_deref() {
                    Some("deny") => target_role_has_deny = true,
                    Some("allow") => target_role_has_allow = true,
                    _ => {} // null means inherit from target
                }
            }
        }

        // Target-role level deny
        if target_role_has_deny {
            info!(
                username,
                target = target_name,
                "File transfer denied by target-role assignment"
            );
            return Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("denied by target-role assignment (SFTP disabled for role on this target)".to_string()),
            });
        }

        // User-role level allow (takes precedence over target default)
        if user_role_has_allow {
            info!(
                username,
                target = target_name,
                "File transfer allowed by user-role assignment"
            );
            return Ok(super::FileTransferAuthResult {
                allowed: true,
                denial_reason: None,
            });
        }

        // Target-role level allow
        if target_role_has_allow {
            info!(
                username,
                target = target_name,
                "File transfer allowed by target-role assignment"
            );
            return Ok(super::FileTransferAuthResult {
                allowed: true,
                denial_reason: None,
            });
        }

        // Fall back to target default
        info!(
            username,
            target = target_name,
            target_allows_sftp,
            "File transfer using target default"
        );
        if target_allows_sftp {
            Ok(super::FileTransferAuthResult {
                allowed: true,
                denial_reason: None,
            })
        } else {
            Ok(super::FileTransferAuthResult {
                allowed: false,
                denial_reason: Some("SFTP/SCP is disabled for this target".to_string()),
            })
        }
    }

    async fn apply_sso_role_mappings(
        &mut self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        assigned_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let user = entities::User::Entity::find()
            .filter(entities::User::Column::Username.eq(username))
            .one(&*db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_role_names = match managed_role_names {
            Some(x) => x,
            None => entities::Role::Entity::find()
                .all(&*db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_role_names.into_iter() {
            let role = entities::Role::Entity::find()
                .filter(entities::Role::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await?
                .ok_or_else(|| WarpgateError::RoleNotFound(role_name.clone()))?;

            let assignment = entities::UserRoleAssignment::Entity::find()
                .filter(entities::UserRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserRoleAssignment::Column::RoleId.eq(role.id))
                .one(&*db)
                .await?;

            match (assignment, assigned_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding role {role_name} for user {username} (from SSO)");
                    let values = entities::UserRoleAssignment::ActiveModel {
                        user_id: Set(user.id),
                        role_id: Set(role.id),
                        ..Default::default()
                    };

                    values.insert(&*db).await?;
                }
                (Some(assignment), false) => {
                    info!("Removing role {role_name} for user {username} (from SSO)");
                    assignment.delete(&*db).await?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let Some(AuthCredential::PublicKey {
            kind,
            public_key_bytes,
        }) = credential
        else {
            error!("Invalid or missing public key credential");
            return Err(WarpgateError::InvalidCredentialType);
        };

        // Encode public key and match it against the database
        let base64_bytes = data_encoding::BASE64.encode(&public_key_bytes);
        let openssh_public_key = format!("{kind} {base64_bytes}");

        debug!(
            "Attempting to update last_used for public key: {}",
            openssh_public_key
        );

        // Find the public key credential
        let public_key_credential = entities::PublicKeyCredential::Entity::find()
            .filter(
                entities::PublicKeyCredential::Column::OpensshPublicKey
                    .eq(openssh_public_key.clone()),
            )
            .one(&*db)
            .await?;

        let Some(public_key_credential) = public_key_credential else {
            warn!(
                "Public key not found in the database: {}",
                openssh_public_key
            );
            return Ok(()); // Gracefully return if the key is not found
        };

        // Update the `last_used` (last used) timestamp
        let mut active_model: entities::PublicKeyCredential::ActiveModel =
            public_key_credential.into();
        active_model.last_used = Set(Some(Utc::now()));

        active_model.update(&*db).await.map_err(|e| {
            error!("Failed to update last_used for public key: {:?}", e);
            WarpgateError::DatabaseError(e)
        })?;

        Ok(())
    }

    async fn validate_api_token(&mut self, token: &str) -> Result<Option<User>, WarpgateError> {
        let db = self.db.lock().await;
        let Some(ticket) = entities::ApiToken::Entity::find()
            .filter(
                entities::ApiToken::Column::Secret
                    .eq(token)
                    .and(entities::ApiToken::Column::Expiry.gt(Utc::now())),
            )
            .one(&*db)
            .await?
        else {
            return Ok(None);
        };

        let Some(user) = ticket
            .find_related(entities::User::Entity)
            .one(&*db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState);
        };

        Ok(Some(user.try_into()?))
    }
}
