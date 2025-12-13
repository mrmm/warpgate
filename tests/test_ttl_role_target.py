"""
Integration tests for Role-Target TTL (time-to-live) functionality.

Tests:
- Expired role-target assignment denies access
- Non-expired assignment allows access
- User with multiple roles, one expired, one valid - can access
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import subprocess
import time
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


def setup_user_with_target_role_ttl(
    processes: ProcessManager,
    wg: WarpgateProcess,
    warpgate_client_key,
    target_role_expires_at=None,
):
    """Setup user, role, and SSH target with optional target-role expiration."""
    ssh_port = processes.start_ssh_server(
        trusted_keys=[warpgate_client_key.read_text()],
    )
    wait_port(ssh_port)

    url = f"https://localhost:{wg.http_port}"
    with admin_client(url) as api:
        role = api.create_role(
            sdk.RoleDataRequest(name=f"role-{uuid4()}"),
        )
        user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
        api.create_password_credential(
            user.id, sdk.NewPasswordCredential(password="123")
        )

        # Add user role (permanent)
        api.add_user_role(user.id, role.id, sdk.UserRoleAssignmentRequest())

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

        # Add target role with optional expiration
        api.add_target_role(
            ssh_target.id,
            role.id,
            sdk.TargetRoleAssignmentRequest(expires_at=target_role_expires_at),
        )

        return user, ssh_target, role


class TestRoleTargetTTL:
    def test_expired_target_role_denies_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Target with expired role-target assignment denies access."""
        # Set target-role expiration to 2 seconds from now, then wait for it to expire
        short_expiry = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        user, ssh_target, role = setup_user_with_target_role_ttl(
            processes, shared_wg, wg_c_ed25519_pubkey,
            target_role_expires_at=short_expiry,
        )

        # Wait for the target-role to expire
        time.sleep(3)

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

        stdout, stderr = ssh_client.communicate(timeout=timeout)
        # Should fail due to expired target-role assignment
        assert ssh_client.returncode != 0

    def test_non_expired_target_role_allows_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """Target with non-expired role-target assignment allows access."""
        # Set expiration to 1 hour from now
        future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        user, ssh_target, role = setup_user_with_target_role_ttl(
            processes, shared_wg, wg_c_ed25519_pubkey,
            target_role_expires_at=future_time,
        )

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

    def test_multiple_roles_one_expired_one_valid(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """User with multiple roles - one expired, one valid - can access."""
        ssh_port = processes.start_ssh_server(
            trusted_keys=[wg_c_ed25519_pubkey.read_text()],
        )
        wait_port(ssh_port)

        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            # Create two roles
            expiring_role = api.create_role(
                sdk.RoleDataRequest(name=f"expiring-role-{uuid4()}"),
            )
            valid_role = api.create_role(
                sdk.RoleDataRequest(name=f"valid-role-{uuid4()}"),
            )

            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))
            api.create_password_credential(
                user.id, sdk.NewPasswordCredential(password="123")
            )

            # Assign both roles to user (permanent user-role)
            api.add_user_role(user.id, expiring_role.id, sdk.UserRoleAssignmentRequest())
            api.add_user_role(user.id, valid_role.id, sdk.UserRoleAssignmentRequest())

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

            # Add short-lived target-role assignment that will expire
            short_expiry = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
            api.add_target_role(
                ssh_target.id,
                expiring_role.id,
                sdk.TargetRoleAssignmentRequest(expires_at=short_expiry),
            )

            # Add valid (permanent) target-role assignment
            api.add_target_role(ssh_target.id, valid_role.id, sdk.TargetRoleAssignmentRequest())

        # Wait for the expiring role to expire
        time.sleep(3)

        # User should still be able to access via the valid role
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

    def test_get_target_roles_returns_expiration_info(
        self,
        shared_wg: WarpgateProcess,
    ):
        """GET /targets/:id/roles should return expiration info."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=22,
                            username="root",
                            allow_sftp=True,
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )

            future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            api.add_target_role(
                ssh_target.id,
                role.id,
                sdk.TargetRoleAssignmentRequest(expires_at=future_time),
            )

            roles = api.get_target_roles(ssh_target.id)
            assert len(roles) == 1
            assert roles[0].expires_at is not None
            assert roles[0].is_expired is False

    def test_update_target_role_expiration(
        self,
        shared_wg: WarpgateProcess,
    ):
        """PUT /targets/:id/roles/:role_id should update expiration."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )

            ssh_target = api.create_target(
                sdk.TargetDataRequest(
                    name=f"ssh-{uuid4()}",
                    options=sdk.TargetOptions(
                        sdk.TargetOptionsTargetSSHOptions(
                            kind="Ssh",
                            host="localhost",
                            port=22,
                            username="root",
                            allow_sftp=True,
                            auth=sdk.SSHTargetAuth(
                                sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                            ),
                        )
                    ),
                )
            )

            # Add role without expiration
            api.add_target_role(ssh_target.id, role.id, sdk.TargetRoleAssignmentRequest())

            # Update with expiration
            new_expiry = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
            updated = api.update_target_role(
                ssh_target.id,
                role.id,
                sdk.TargetRoleAssignmentRequest(expires_at=new_expiry),
            )

            assert updated.expires_at is not None
