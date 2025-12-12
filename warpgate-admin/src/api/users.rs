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
    Role as RoleConfig, User as UserConfig, UserRequireCredentialsPolicy, WarpgateError,
};
use warpgate_core::Services;
use warpgate_db_entities::{Role, User, UserRoleAssignment};

use super::AnySecurityScheme;

#[derive(Object)]
struct CreateUserRequest {
    username: String,
    description: Option<String>,
}

#[derive(Object)]
struct UserDataRequest {
    username: String,
    credential_policy: Option<UserRequireCredentialsPolicy>,
    description: Option<String>,
    rate_limit_bytes_per_second: Option<u32>,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserConfig>>),
}
#[derive(ApiResponse)]
enum CreateUserResponse {
    #[oai(status = 201)]
    Created(Json<UserConfig>),

    #[oai(status = 400)]
    BadRequest(Json<String>),
}

pub struct ListApi;

#[OpenApi]
impl ListApi {
    #[oai(path = "/users", method = "get", operation_id = "get_users")]
    async fn api_get_all_users(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        search: Query<Option<String>>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUsersResponse, WarpgateError> {
        let db = db.lock().await;

        let mut users = User::Entity::find().order_by_asc(User::Column::Username);

        if let Some(ref search) = *search {
            let search = format!("%{search}%");
            users = users.filter(User::Column::Username.like(search));
        }

        let users = users.all(&*db).await.map_err(WarpgateError::from)?;

        let users: Vec<UserConfig> = users
            .into_iter()
            .map(UserConfig::try_from)
            .collect::<Result<Vec<UserConfig>, _>>()?;

        Ok(GetUsersResponse::Ok(Json(users)))
    }

    #[oai(path = "/users", method = "post", operation_id = "create_user")]
    async fn api_create_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        body: Json<CreateUserRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<CreateUserResponse, WarpgateError> {
        if body.username.is_empty() {
            return Ok(CreateUserResponse::BadRequest(Json("name".into())));
        }

        let db = db.lock().await;

        let values = User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(body.username.clone()),
            credential_policy: Set(
                serde_json::to_value(UserRequireCredentialsPolicy::default())
                    .map_err(WarpgateError::from)?,
            ),
            description: Set(body.description.clone().unwrap_or_default()),
            rate_limit_bytes_per_second: Set(None),
        };

        let user = values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(CreateUserResponse::Created(Json(user.try_into()?)))
    }
}

#[derive(ApiResponse)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserConfig>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

pub struct DetailApi;

#[OpenApi]
impl DetailApi {
    #[oai(path = "/users/:id", method = "get", operation_id = "get_user")]
    async fn api_get_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(GetUserResponse::NotFound);
        };

        Ok(GetUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "put", operation_id = "update_user")]
    async fn api_update_user(
        &self,
        services: Data<&Services>,
        body: Json<UserDataRequest>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserResponse, WarpgateError> {
        let db = services.db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateUserResponse::NotFound);
        };

        let mut model: User::ActiveModel = user.into();
        model.username = Set(body.username.clone());
        model.description = Set(body.description.clone().unwrap_or_default());
        model.credential_policy =
            Set(serde_json::to_value(body.credential_policy.clone())
                .map_err(WarpgateError::from)?);
        model.rate_limit_bytes_per_second = Set(body.rate_limit_bytes_per_second.map(|x| x as i64));
        let user = model.update(&*db).await?;

        drop(db);

        services
            .rate_limiter_registry
            .lock()
            .await
            .apply_new_rate_limits(&mut *services.state.lock().await)
            .await?;

        Ok(UpdateUserResponse::Ok(Json(user.try_into()?)))
    }

    #[oai(path = "/users/:id", method = "delete", operation_id = "delete_user")]
    async fn api_delete_user(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserResponse::NotFound);
        };

        UserRoleAssignment::Entity::delete_many()
            .filter(UserRoleAssignment::Column::UserId.eq(user.id))
            .exec(&*db)
            .await?;

        user.delete(&*db).await?;
        Ok(DeleteUserResponse::Deleted)
    }
}

/// Request body for creating or updating a user role assignment
#[derive(Object, Default)]
struct UserRoleAssignmentRequest {
    /// Optional expiration date for the role assignment. If null, the assignment is permanent.
    expires_at: Option<DateTime<Utc>>,
}

/// Response containing role assignment details with expiration info
#[derive(Object)]
struct UserRoleAssignmentResponse {
    /// The role details
    role: RoleConfig,
    /// Expiration date of the assignment, if any
    expires_at: Option<DateTime<Utc>>,
    /// Whether the assignment has expired
    is_expired: bool,
}

#[derive(ApiResponse)]
enum GetUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserRoleAssignmentResponse>>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum AddUserRoleResponse {
    #[oai(status = 201)]
    Created,
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 409)]
    AlreadyExists,
}

#[derive(ApiResponse)]
enum UpdateUserRoleResponse {
    #[oai(status = 200)]
    Ok(Json<UserRoleAssignmentResponse>),
    #[oai(status = 400)]
    BadRequest(Json<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteUserRoleResponse {
    #[oai(status = 204)]
    Deleted,
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum DeleteExpiredUserRolesResponse {
    #[oai(status = 200)]
    Ok(Json<u64>),
    #[oai(status = 404)]
    NotFound,
}

pub struct RolesApi;

#[OpenApi]
impl RolesApi {
    #[oai(
        path = "/users/:id/roles",
        method = "get",
        operation_id = "get_user_roles"
    )]
    async fn api_get_user_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<GetUserRolesResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(user) = User::Entity::find_by_id(*id).one(&*db).await? else {
            return Ok(GetUserRolesResponse::NotFound);
        };

        // Get all role assignments with their expiration info
        let assignments = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(user.id))
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

            responses.push(UserRoleAssignmentResponse {
                role: role.into(),
                expires_at: assignment.expires_at,
                is_expired,
            });
        }

        Ok(GetUserRolesResponse::Ok(Json(responses)))
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "post",
        operation_id = "add_user_role"
    )]
    async fn api_add_user_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<UserRoleAssignmentRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<AddUserRoleResponse, WarpgateError> {
        let db = db.lock().await;

        // Validate expires_at is not in the past
        if let Some(expires_at) = body.expires_at {
            if expires_at < Utc::now() {
                return Ok(AddUserRoleResponse::BadRequest(Json(
                    "expires_at cannot be in the past".into(),
                )));
            }
        }

        if !UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .all(&*db)
            .await
            .map_err(WarpgateError::from)?
            .is_empty()
        {
            return Ok(AddUserRoleResponse::AlreadyExists);
        }

        let values = UserRoleAssignment::ActiveModel {
            user_id: Set(id.0),
            role_id: Set(role_id.0),
            expires_at: Set(body.expires_at),
            ..Default::default()
        };

        values.insert(&*db).await.map_err(WarpgateError::from)?;

        Ok(AddUserRoleResponse::Created)
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "put",
        operation_id = "update_user_role"
    )]
    async fn api_update_user_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        body: Json<UserRoleAssignmentRequest>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<UpdateUserRoleResponse, WarpgateError> {
        let db = db.lock().await;

        // Validate expires_at is not in the past (if provided)
        if let Some(expires_at) = body.expires_at {
            if expires_at < Utc::now() {
                return Ok(UpdateUserRoleResponse::BadRequest(Json(
                    "expires_at cannot be in the past".into(),
                )));
            }
        }

        let Some(_user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleResponse::NotFound);
        };

        let Some(role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(UpdateUserRoleResponse::NotFound);
        };

        let Some(assignment) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await?
        else {
            return Ok(UpdateUserRoleResponse::NotFound);
        };

        let mut model: UserRoleAssignment::ActiveModel = assignment.into();
        model.expires_at = Set(body.expires_at);
        let updated = model.update(&*db).await?;

        let now = Utc::now();
        let is_expired = updated.expires_at.map(|exp| exp < now).unwrap_or(false);

        Ok(UpdateUserRoleResponse::Ok(Json(UserRoleAssignmentResponse {
            role: role.into(),
            expires_at: updated.expires_at,
            is_expired,
        })))
    }

    #[oai(
        path = "/users/:id/roles/:role_id",
        method = "delete",
        operation_id = "delete_user_role"
    )]
    async fn api_delete_user_role(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        role_id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteUserRoleResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(_user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(_role) = Role::Entity::find_by_id(role_id.0).one(&*db).await? else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        let Some(model) = UserRoleAssignment::Entity::find()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::RoleId.eq(role_id.0))
            .one(&*db)
            .await
            .map_err(WarpgateError::from)?
        else {
            return Ok(DeleteUserRoleResponse::NotFound);
        };

        model.delete(&*db).await.map_err(WarpgateError::from)?;

        Ok(DeleteUserRoleResponse::Deleted)
    }

    #[oai(
        path = "/users/:id/roles/expired",
        method = "delete",
        operation_id = "delete_expired_user_roles"
    )]
    async fn api_delete_expired_user_roles(
        &self,
        db: Data<&Arc<Mutex<DatabaseConnection>>>,
        id: Path<Uuid>,
        _sec_scheme: AnySecurityScheme,
    ) -> Result<DeleteExpiredUserRolesResponse, WarpgateError> {
        let db = db.lock().await;

        let Some(_user) = User::Entity::find_by_id(id.0).one(&*db).await? else {
            return Ok(DeleteExpiredUserRolesResponse::NotFound);
        };

        let now = Utc::now();
        let result = UserRoleAssignment::Entity::delete_many()
            .filter(UserRoleAssignment::Column::UserId.eq(id.0))
            .filter(UserRoleAssignment::Column::ExpiresAt.is_not_null())
            .filter(UserRoleAssignment::Column::ExpiresAt.lt(now))
            .exec(&*db)
            .await?;

        Ok(DeleteExpiredUserRolesResponse::Ok(Json(result.rows_affected)))
    }
}
