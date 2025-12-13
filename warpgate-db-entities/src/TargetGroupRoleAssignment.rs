use poem_openapi::Object;
use sea_orm::entity::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Object)]
#[sea_orm(table_name = "target_group_roles")]
#[oai(rename = "TargetGroupRoleAssignment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    pub target_group_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter)]
pub enum Relation {
    TargetGroup,
    Role,
}

impl RelationTrait for Relation {
    fn def(&self) -> RelationDef {
        match self {
            Self::TargetGroup => Entity::belongs_to(super::TargetGroup::Entity)
                .from(Column::TargetGroupId)
                .to(super::TargetGroup::Column::Id)
                .into(),
            Self::Role => Entity::belongs_to(super::Role::Entity)
                .from(Column::RoleId)
                .to(super::Role::Column::Id)
                .into(),
        }
    }
}

impl ActiveModelBehavior for ActiveModel {}
