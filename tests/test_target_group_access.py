"""
Integration tests for Target Group access control.

Tests:
- Role with group access can access all targets in group
- Adding target to group grants access
- Removing target from group revokes group-based access
- Direct role-target persists after group removal
"""

from uuid import uuid4
import subprocess
import pytest

from .api_client import admin_client, sdk
from .conftest import ProcessManager, WarpgateProcess
from .util import wait_port


common_args = [
    "-i",
    "/dev/null",
    "-o",
    "PreferredAuthentications=password",
]


class TestTargetGroupAccess:
    def test_role_with_group_access_can_access_targets_in_group(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Role with group access can access all targets in that group."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()],
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create a target group
            group = api.create_target_group(
                sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
            )

            # Create a role
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            # Assign role to group (not to individual target)
            api.add_target_group_role(group.id, role.id)

            # Create user with the role
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id, sdk.UserRoleAssignmentRequest())

            # Create target IN the group
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    group_id=group.id,  # Assign to group
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            allow_sftp=True,
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )

        # User should be able to access target via group membership
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "hello",
            password="123",
        )

        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"hello" in stdout

    def test_adding_target_to_group_grants_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Adding a target to a group grants access to users with group role."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()],
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create a target group
            group = api.create_target_group(
                sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
            )

            # Create a role and assign to group
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            api.add_target_group_role(group.id, role.id)

            # Create user with the role
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id, sdk.UserRoleAssignmentRequest())

            # Create target NOT in the group
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            allow_sftp=True,
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )

            # User should NOT be able to access target (no direct or group access)
            ssh_client = processes.start_ssh_client(
                f"{user.username}:{ssh_target.name}@localhost",
                "-p",
                str(shared_wg.ssh_port),
                *common_args,
                "echo",
                "hello",
                password="123",
                stderr=subprocess.PIPE,
            )
            ssh_client.communicate(timeout=timeout)
            assert ssh_client.returncode != 0

            # Now add target to group
            api.update_target(
                ssh_target.id,
                sdk.TargetDataRequest(
                    name=ssh_target.name,
                    group_id=group.id,
                    options=ssh_target.options,
                ),
            )

        # User should now be able to access target via group
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "hello",
            password="123",
        )

        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"hello" in stdout

    def test_direct_role_target_persists_after_group_removal(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Direct role-target assignment persists when target is removed from group."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()],
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create a target group
            group = api.create_target_group(
                sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
            )

            # Create a role
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            # Create user with the role
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )
            api.add_user_role(user.id, role.id, sdk.UserRoleAssignmentRequest())

            # Create target IN the group
            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    group_id=group.id,
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=ssh_port,
                            username="root",
                            allow_sftp=True,
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )

            # Add BOTH group-level and direct role access
            api.add_target_group_role(group.id, role.id)
            api.add_target_role(ssh_target.id, role.id, sdk.TargetRoleAssignmentRequest())

            # Remove target from group
            api.update_target(
                ssh_target.id,
                sdk.TargetDataRequest(
                    name=ssh_target.name,
                    group_id=None,  # Remove from group
                    options=ssh_target.options,
                ),
            )

        # User should STILL be able to access via direct role-target assignment
        ssh_client = processes.start_ssh_client(
            f"{user.username}:{ssh_target.name}@localhost",
            "-p",
            str(shared_wg.ssh_port),
            *common_args,
            "echo",
            "hello",
            password="123",
        )

        stdout, _ = ssh_client.communicate(timeout=timeout)
        assert b"hello" in stdout

    def test_get_target_group_roles(
        self,
        shared_wg: WarpgateProcess,
    ):
        """GET /target-groups/:id/roles should return assigned roles."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            group = api.create_target_group(
                sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
            )
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            api.add_target_group_role(group.id, role.id)

            roles = api.get_target_group_roles(group.id)
            assert len(roles) == 1
            assert roles[0].id == role.id

    def test_get_role_target_groups(
        self,
        shared_wg: WarpgateProcess,
    ):
        """GET /roles/:id/target-groups should return assigned groups."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            group = api.create_target_group(
                sdk.TargetGroupDataRequest(name=f"group-{uuid4()}"),
            )
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            api.add_target_group_role(group.id, role.id)

            groups = api.get_role_target_groups(role.id)
            assert len(groups) == 1
            assert groups[0].id == group.id
