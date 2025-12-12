"""
Integration tests for User-Role TTL (time-to-live) functionality.

Tests:
- User with expired role cannot access targets
- User with non-expired role can access targets
- Null expires_at means permanent access
- API rejects expires_at in past
"""

from datetime import datetime, timedelta, timezone
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


def setup_user_role_target(
    processes: ProcessManager,
    wg: WarpgateProcess,
    warpgate_client_key,
    expires_at=None,
):
    """Setup user, role, and SSH target with optional role expiration."""
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

        # Add user role with optional expiration
        api.add_user_role(
            user.id,
            role.id,
            sdk.UserRoleAssignmentRequest(expires_at=expires_at),
        )

        ssh_target = api.create_target(
            sdk.TargetDataRequest(
                name=f"ssh-{uuid4()}",
                options=sdk.TargetOptions(
                    sdk.TargetOptionsTargetSSHOptions(
                        kind="Ssh",
                        host="localhost",
                        port=ssh_port,
                        username="root",
                        auth=sdk.SSHTargetAuth(
                            sdk.SSHTargetAuthSshTargetPublicKeyAuth(kind="PublicKey")
                        ),
                    )
                ),
            )
        )
        api.add_target_role(ssh_target.id, role.id)
        return user, ssh_target, role


class TestUserRoleTTL:
    def test_expired_user_role_denies_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """User with expired role assignment cannot access targets."""
        # Set expiration to 1 second ago
        expired_time = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()

        user, ssh_target, role = setup_user_role_target(
            processes, shared_wg, wg_c_ed25519_pubkey,
            expires_at=expired_time,
        )

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
        # Should fail due to expired role
        assert ssh_client.returncode != 0

    def test_non_expired_user_role_allows_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """User with non-expired role assignment can access targets."""
        # Set expiration to 1 hour from now
        future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        user, ssh_target, role = setup_user_role_target(
            processes, shared_wg, wg_c_ed25519_pubkey,
            expires_at=future_time,
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

    def test_null_expires_at_means_permanent_access(
        self,
        processes: ProcessManager,
        timeout,
        wg_c_ed25519_pubkey,
        shared_wg: WarpgateProcess,
    ):
        """User role with null expires_at has permanent access."""
        user, ssh_target, role = setup_user_role_target(
            processes, shared_wg, wg_c_ed25519_pubkey,
            expires_at=None,  # Permanent
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

    def test_api_rejects_past_expires_at(
        self,
        shared_wg: WarpgateProcess,
    ):
        """API should reject expires_at dates in the past."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))

            # Try to add role with past expiration
            past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

            try:
                api.add_user_role(
                    user.id,
                    role.id,
                    sdk.UserRoleAssignmentRequest(expires_at=past_time),
                )
                assert False, "Should have rejected past expires_at"
            except sdk.ApiException as e:
                assert e.status == 400

    def test_get_user_roles_returns_expiration_info(
        self,
        shared_wg: WarpgateProcess,
    ):
        """GET /users/:id/roles should return expiration info."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))

            future_time = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            api.add_user_role(
                user.id,
                role.id,
                sdk.UserRoleAssignmentRequest(expires_at=future_time),
            )

            roles = api.get_user_roles(user.id)
            assert len(roles) == 1
            assert roles[0].expires_at is not None
            assert roles[0].is_expired is False

    def test_update_user_role_expiration(
        self,
        shared_wg: WarpgateProcess,
    ):
        """PUT /users/:id/roles/:role_id should update expiration."""
        url = f"https://localhost:{shared_wg.http_port}"
        with admin_client(url) as api:
            role = api.create_role(
                sdk.RoleDataRequest(name=f"role-{uuid4()}"),
            )
            user = api.create_user(sdk.CreateUserRequest(username=f"user-{uuid4()}"))

            # Add role without expiration
            api.add_user_role(user.id, role.id)

            # Update with expiration
            new_expiry = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
            updated = api.update_user_role(
                user.id,
                role.id,
                sdk.UserRoleAssignmentRequest(expires_at=new_expiry),
            )

            assert updated.expires_at is not None
