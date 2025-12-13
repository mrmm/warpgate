use sea_orm::Schema;
use sea_orm_migration::prelude::*;

use crate::m00007_targets_and_roles::role;
use crate::m00020_target_groups::target_group;

// Entity definition for the new target_group_roles junction table
pub mod target_group_role_assignment {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_group_roles")]
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
                Self::TargetGroup => Entity::belongs_to(super::target_group::Entity)
                    .from(Column::TargetGroupId)
                    .to(super::target_group::Column::Id)
                    .into(),
                Self::Role => Entity::belongs_to(super::role::Entity)
                    .from(Column::RoleId)
                    .to(super::role::Column::Id)
                    .into(),
            }
        }
    }

    impl ActiveModelBehavior for ActiveModel {}
}

// Table aliases for existing tables
mod user_roles {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "user_roles")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod target_roles {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "target_roles")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i32,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00021_role_assignment_ttl"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add expires_at column to user_roles table
        manager
            .alter_table(
                Table::alter()
                    .table(user_roles::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("expires_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add expires_at column to target_roles table
        manager
            .alter_table(
                Table::alter()
                    .table(target_roles::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("expires_at"))
                            .timestamp_with_time_zone()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Create index on user_roles.expires_at for query performance
        manager
            .create_index(
                Index::create()
                    .name("idx_user_roles_expires_at")
                    .table(user_roles::Entity)
                    .col(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        // Create index on target_roles.expires_at for query performance
        manager
            .create_index(
                Index::create()
                    .name("idx_target_roles_expires_at")
                    .table(target_roles::Entity)
                    .col(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        // Create target_group_roles table
        let builder = manager.get_database_backend();
        let schema = Schema::new(builder);
        manager
            .create_table(schema.create_table_from_entity(target_group_role_assignment::Entity))
            .await?;

        // Create unique constraint on (target_group_id, role_id)
        manager
            .create_index(
                Index::create()
                    .name("idx_target_group_roles_unique")
                    .table(target_group_role_assignment::Entity)
                    .col(Alias::new("target_group_id"))
                    .col(Alias::new("role_id"))
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop target_group_roles table and its index
        manager
            .drop_index(
                Index::drop()
                    .name("idx_target_group_roles_unique")
                    .table(target_group_role_assignment::Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(target_group_role_assignment::Entity)
                    .to_owned(),
            )
            .await?;

        // Drop indexes
        manager
            .drop_index(
                Index::drop()
                    .name("idx_target_roles_expires_at")
                    .table(target_roles::Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_user_roles_expires_at")
                    .table(user_roles::Entity)
                    .to_owned(),
            )
            .await?;

        // Drop expires_at columns
        manager
            .alter_table(
                Table::alter()
                    .table(target_roles::Entity)
                    .drop_column(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(user_roles::Entity)
                    .drop_column(Alias::new("expires_at"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
