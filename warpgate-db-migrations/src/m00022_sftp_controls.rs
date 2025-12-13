use sea_orm_migration::prelude::*;

// Table alias for existing target_roles table
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

// Table alias for existing user_roles table
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

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m00022_sftp_controls"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add allow_file_transfer column to target_roles table
        // Values: "allow", "deny", or NULL (inherit from target)
        manager
            .alter_table(
                Table::alter()
                    .table(target_roles::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_transfer"))
                            .string_len(16)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add allow_file_transfer column to user_roles table
        // Values: "allow", "deny", or NULL (allow by default)
        manager
            .alter_table(
                Table::alter()
                    .table(user_roles::Entity)
                    .add_column(
                        ColumnDef::new(Alias::new("allow_file_transfer"))
                            .string_len(16)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop allow_file_transfer column from target_roles
        manager
            .alter_table(
                Table::alter()
                    .table(target_roles::Entity)
                    .drop_column(Alias::new("allow_file_transfer"))
                    .to_owned(),
            )
            .await?;

        // Drop allow_file_transfer column from user_roles
        manager
            .alter_table(
                Table::alter()
                    .table(user_roles::Entity)
                    .drop_column(Alias::new("allow_file_transfer"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
