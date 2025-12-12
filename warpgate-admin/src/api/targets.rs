use std::sync::Arc;

use chrono::{DateTime, Utc};
use poem::web::Data;
use poem_openapi::param::{Path, Query};
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, ModelTrait, QueryFilter,
    QueryOrder, Set,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use warpgate_common::{
    Role as RoleConfig, Target as TargetConfig, TargetOptions, TargetSSHOptions, WarpgateError,
};
use warpgate_core::consts::BUILTIN_ADMIN_ROLE_NAME;
use warpgate_core::Services;
use warpgate_db_entities::Target::TargetKind;
use warpgate_db_entities::{KnownHost, Role, Target, TargetRoleAssignment};

use super::AnySecurityScheme;

#[derive(Object)]
struct TargetDataRequest {
    name: String,
    description: Option<String>,
    options: TargetOptions,
    rate_limit_bytes_per_second: Option<u32>,
    group_id: Option<Uuid>,
}

#[derive(ApiResponse)]
enum GetTargetsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetConfig>>),
}

#[derive(ApiResponse)]
enum CreateTargetResponse {
    #[oai(status = 201)]
    Created(Json<TargetConfig>),

    #[oai(status = 409)]
    Conflict(Json<String>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/targets", method = "get", operation_id = "get_targets")]
    async fn api_get_all_targets(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        group_id: Query<Option<Uuid>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetsResponse, WarpgateError> {
        let db = db.lock().await;

        let mut targets = Target::Entity::find().order_by_asc(Target::Column::Name);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            targets = targets.filter(Target::Column::Name.like(search));
        }

        if let Some(group_id) = *group_id {
            targets = targets.filter(Target::Column::GroupId.eq(group_id));
        }

        let targets = targets.all(&*db).await.map_err(WarpgateError::from)?;

        let targets: Result<Vec<TargetConfig>, _> =
            targets.into_iter().map(|t| t.try_into()).collect();
        let targets = targets.map_err(WarpgateError::from)?;

        Ok(GetTargetsResponse::Ok(Json(targets)))
    }

    #[oai(path = "/targets", method = "post", operation_id = "create_target")]
    async fn api_create_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<TargetDataRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateTargetResponse, WarpgateError> {
        if body.name.is_empty() {
            return Ok(CreateTargetResponse::BadRequest(Json("name".into())));
        }

        if let TargetOptions::WebAdmin(_) = body.options {
            return Ok(CreateTargetResponse::BadRequest(Json("kind".into())));
        }

        let db = db.lock().await;
        let existing = Target::Entity::find()
            .filter(Target::Column::Name.eq(body.name.clone()))
            .one(&*db)
            .await?;
        if existing.is_some() {
            return Ok(CreateTargetResponse::Conflict(Json(
                "Name already exists".into(),
            )));
        }

        let values = Target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(body.name.clone()),
            description: Set(body.description.clone().unwrap_or_default()),
            kind: Set((&body.options).into()),
            options: Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?),
            rate_limit_bytes_per_second: Set(None),
            group_id: Set(body.group_id),
        };

        let target = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateTargetResponse::Created(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }
}

#[derive(ApiResponse)]
enum GetTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateTargetResponse {
    #[oai(status = 200)]
    Ok(Json<TargetConfig>),
    #[oai(status = 400)]
    BadRequest,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 403)]
    Forbidden,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum TargetKnownSshHostKeysResponse {
    #[oai(status = 200)]
    Found(Json<Vec<KnownHost::Model>>),

    #[oai(status = 400)]
    InvalidType,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/targets/:id", method = "get", operation_id = "get_target")]
    async fn api_get_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetTargetResponse::NotFound);
        };

        Ok(GetTargetResponse::Ok(Json(target.try_into()?)))
    }

    #[oai(path = "/targets/:id", method = "put", operation_id = "update_target")]
    async fn api_update_target(
        &self,
        services: Data<&Services>,
        body: Json<TargetDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateTargetResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateTargetResponse::NotFound);
        };

        if target.kind != (&body.options).into() {
            return Ok(UpdateTargetResponse::BadRequest);
        }

        let mut model: Target::ActiveModel = target.into();
        model.name = Set(body.name.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.options =
            Set(serde_json::to_value(body.options.clone()).map_err(WarpgateError::from)?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        model.group_id = Set(body.group_id);
        let target = model.update(&*db).await?;

        drop(db);

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *services.state.lock().await)
            .await?;

        Ok(UpdateTargetResponse::Ok(Json(
            target.try_into().map_err(WarpgateError::from)?,
        )))
    }

    #[oai(
        path = "/targets/:id",
        method = "delete",
        operation_id = "delete_target"
    )]
    async fn api_delete_target(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTargetResponse::NotFound);
        };

        if target.kind == TargetKind::WebAdmin {
            return Ok(DeleteTargetResponse::Forbidden);
        }

        TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
            .exec(&*db)
            .await?;

        if target.kind == TargetKind::Ssh {
            let options: TargetOptions = serde_json::from_value(target.options.clone())?;
            if let TargetOptions::Ssh(ssh_options) = options {
                use warpgate_db_entities::KnownHost;
                KnownHost::Entity::delete_many()
                    .filter(KnownHost::Column::Host.eq(&ssh_options.host))
                    .filter(KnownHost::Column::Port.eq(ssh_options.port as i32))
                    .exec(&*db)
                    .await?;
            }
        }

        target.delete(&*db).await?;
        Ok(DeleteTargetResponse::Deleted)
    }

    #[oai(
        path = "/targets/:id/known-ssh-host-keys",
        method = "get",
        operation_id = "get_ssh_target_known_ssh_host_keys"
    )]
    async fn get_ssh_target_known_ssh_host_keys(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<TargetKnownSshHostKeysResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(TargetKnownSshHostKeysResponse::NotFound);
        };

        let target: TargetConfig = target.try_into()?;

        let options: TargetSSHOptions = match target.options {
            TargetOptions::Ssh(x) => x,
            _ => return Ok(TargetKnownSshHostKeysResponse::InvalidType),
        };

        let known_hosts = KnownHost::Entity::find()
            .filter(
                KnownHost::Column::Host
                    .eq(&options.host)
                    .and(KnownHost::Column::Port.eq(options.port)),
            )
            .all(&*db)
            .await?;

        Ok(TargetKnownSshHostKeysResponse::Found(Json(known_hosts)))
    }
}

/// Request body for creating or updating a target role assignment
#[derive(Object, Default)]
struct TargetRoleAssignmentRequest {
    /// Optional expiration date for the role assignment. If null, the assignment is permanent.
    expires_at: Option<DateTime<Utc>>,
    /// SFTP/SCP file transfer permission override. Values: "allow", "deny", or null (inherit from target)
    allow_file_transfer: Option<String>,
}

/// Response containing role assignment details with expiration info
#[derive(Object)]
struct TargetRoleAssignmentResponse {
    /// The role details
    role: RoleConfig,
    /// Expiration date of the assignment, if any
    expires_at: Option<DateTime<Utc>>,
    /// Whether the assignment has expired
    is_expired: bool,
    /// SFTP/SCP file transfer permission override. Values: "allow", "deny", or null (inherit from target)
    allow_file_transfer: Option<String>,
}

#[derive(ApiResponse)]
enum GetTargetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<TargetRoleAssignmentResponse>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddTargetRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum UpdateTargetRoleResponse {
    #[oai(status = 200)]
    Ok(Json<TargetRoleAssignmentResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteTargetRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteExpiredTargetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<u64>),
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/targets/:id/roles",
        method = "get",
        operation_id = "get_target_roles"
    )]
    async fn api_get_target_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetTargetRolesResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(*id).one(&*db).await? else {
            return Ok(GetTargetRolesResponse::NotFound);
        };

        // Get all role assignments with their expiration info
        let assignments = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(target.id))
            .all(&*db)
            .await?;

        let now = Utc::now();
        let mut responses = Vec::new();

        for assignment in assignments {
            let Some(role) = Role::Entity::find_by_id(assignment.role_id)
                .one(&*db)
                .await?
            else {
                continue;
            };

            let is_expired = assignment
                .expires_at
                .map(|exp| exp < now)
                .unwrap_or(false);

            responses.push(TargetRoleAssignmentResponse {
                role: role.into(),
                expires_at: assignment.expires_at,
                is_expired,
                allow_file_transfer: assignment.allow_file_transfer.clone(),
            });
        }

        Ok(GetTargetRolesResponse::Ok(Json(responses)))
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "post",
        operation_id = "add_target_role"
    )]
    async fn api_add_target_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<TargetRoleAssignmentRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddTargetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        // Validate expires_at is not in the past
        if let Some(expires_at) = body.expires_at {
            if expires_at < Utc::now() {
                return Ok(AddTargetRoleResponse::BadRequest(Json(
                    "expires_at cannot be in the past".into(),
                )));
            }
        }

        if !TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddTargetRoleResponse::AlreadyExists);
        }

        let values = TargetRoleAssignment::ActiveModel {
            target_id: Set(id.0),
            role_id: Set(role_id.0),
            expires_at: Set(body.expires_at),
            allow_file_transfer: Set(body.allow_file_transfer.clone()),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(AddTargetRoleResponse::Created)
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "put",
        operation_id = "update_target_role"
    )]
    async fn api_update_target_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<TargetRoleAssignmentRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateTargetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        // Validate expires_at is not in the past (if provided)
        if let Some(expires_at) = body.expires_at {
            if expires_at < Utc::now() {
                return Ok(UpdateTargetRoleResponse::BadRequest(Json(
                    "expires_at cannot be in the past".into(),
                )));
            }
        }

        let Some(_target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateTargetRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(UpdateTargetRoleResponse::NotFound);
        };

        let Some(assignment) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(UpdateTargetRoleResponse::NotFound);
        };

        let mut model: TargetRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(body.expires_at);
        model.allow_file_transfer = Set(body.allow_file_transfer.clone());
        let updated = model.update(&*db).await?;

        let now = Utc::now();
        let is_expired = updated.expires_at.map(|exp| exp < now).unwrap_or(false);

        Ok(UpdateTargetRoleResponse::Ok(Json(TargetRoleAssignmentResponse {
            role: role.into(),
            expires_at: updated.expires_at,
            is_expired,
            allow_file_transfer: updated.allow_file_transfer,
        })))
    }

    #[oai(
        path = "/targets/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_target_role"
    )]
    async fn api_delete_target_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteTargetRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        if role.name == BUILTIN_ADMIN_ROLE_NAME && target.kind == TargetKind::WebAdmin {
            return Ok(DeleteTargetRoleResponse::Forbidden);
        }

        let Some(model) = TargetRoleAssignment::Entity::find()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteTargetRoleResponse::NotFound);
        };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        Ok(DeleteTargetRoleResponse::Deleted)
    }

    #[oai(
        path = "/targets/:id/roles/expired",
        method = "delete",
        operation_id = "delete_expired_target_roles"
    )]
    async fn api_delete_expired_target_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteExpiredTargetRolesResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(_target) = Target::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteExpiredTargetRolesResponse::NotFound);
        };

        let now = Utc::now();
        let result = TargetRoleAssignment::Entity::delete_many()
            .filter(TargetRoleAssignment::Column::TargetId.eq(id.0))
            .filter(TargetRoleAssignment::Column::ExpiresAt.is_not_null())
            .filter(TargetRoleAssignment::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        Ok(DeleteExpiredTargetRolesResponse::Ok(Json(result.rows_affected)))
    }
}
