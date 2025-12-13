use chrono::{DateTime, Utc};
use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "target_roles")]
#[oai(rename = "TargetRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub target_id: Uuid,
    pub role_id: Uuid,
    #[sea_orm(nullable)]
    pub expires_at: Option<DateTime<Utc>>,
    /// SFTP/SCP file transfer permission for this role-target assignment.
    /// Values: "allow", "deny", or null (inherit from target)
    #[sea_orm(column_type = "String(StringLen::N(16))", nullable)]
    pub allow_file_transfer: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    Target,
    Role,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::Target => Entity::belongs_to(super::Target::Entity)
                .from(Column::TargetId)
                .to(super::Target::Column::Id)
                .into(),
            Self::Role => Entity::belongs_to(super::Role::Entity)
                .from(Column::RoleId)
                .to(super::Role::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
