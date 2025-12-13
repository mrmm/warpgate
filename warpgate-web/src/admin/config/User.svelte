<script lang="ts">
    import { api, type Role, type User, type UserRoleAssignmentResponse } from 'admin/lib/api'
    import AsyncButton from 'common/AsyncButton.svelte'
    import { replace } from 'svelte-spa-router'
    import { FormGroup, Input } from '@sveltestrap/sveltestrap'
    import Badge from 'common/sveltestrap-s5-ports/Badge.svelte'
    import { stringifyError } from 'common/errors'
    import Alert from 'common/sveltestrap-s5-ports/Alert.svelte'
    import CredentialEditor from '../CredentialEditor.svelte'
    import Loadable from 'common/Loadable.svelte'
    import RateLimitInput from 'common/RateLimitInput.svelte'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()

    let error: string|null = $state(null)
    let user: User | undefined = $state()
    let allRoles: Role[] = $state([])
    let roleAssignments: Record<string, UserRoleAssignmentResponse | null> = $state({})
    let roleExpirationInputs: Record<string, string> = $state({})
    let roleFileTransferInputs: Record<string, string | undefined> = $state({})

    const initPromise = init()

    async function init () {
        user = await api.getUser({ id: params.id })
        user.credentialPolicy ??= {}

        allRoles = await api.getRoles()
        const assignments = await api.getUserRoles(user)
        roleAssignments = Object.fromEntries(assignments.map(a => [a.role.id, a]))
    }

    async function update () {
        try {
            user = await api.updateUser({
                id: params.id,
                userDataRequest: user!,
            })
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function remove () {
        if (confirm(`Delete user ${user!.username}?`)) {
            await api.deleteUser(user!)
            replace('/config/users')
        }
    }

    async function toggleRole (role: Role) {
        error = null
        try {
            if (roleAssignments[role.id]) {
                await api.deleteUserRole({
                    id: user!.id,
                    roleId: role.id,
                })
                roleAssignments = { ...roleAssignments, [role.id]: null }
            } else {
                const expiresAtInput = roleExpirationInputs[role.id]
                const expiresAt = expiresAtInput ? new Date(expiresAtInput) : undefined
                const allowFileTransfer = roleFileTransferInputs[role.id] || undefined
                await api.addUserRole({
                    id: user!.id,
                    roleId: role.id,
                    userRoleAssignmentRequest: { expiresAt, allowFileTransfer },
                })
                // Refetch to get the full assignment info
                const assignments = await api.getUserRoles(user!)
                roleAssignments = Object.fromEntries(assignments.map(a => [a.role.id, a]))
            }
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    async function updateRoleAssignment (role: Role) {
        error = null
        try {
            const expiresAtInput = roleExpirationInputs[role.id]
            const expiresAt = expiresAtInput ? new Date(expiresAtInput) : undefined
            const allowFileTransfer = roleFileTransferInputs[role.id] || undefined
            await api.updateUserRole({
                id: user!.id,
                roleId: role.id,
                userRoleAssignmentRequest: { expiresAt, allowFileTransfer },
            })
            // Refetch to get updated assignment
            const assignments = await api.getUserRoles(user!)
            roleAssignments = Object.fromEntries(assignments.map(a => [a.role.id, a]))
        } catch (err) {
            error = await stringifyError(err)
        }
    }

    function formatExpirationDate (date: Date | null | undefined): string {
        if (!date) return ''
        return date.toLocaleString()
    }

    function toInputDatetime (date: Date | null | undefined): string {
        if (!date) return ''
        return date.toISOString().slice(0, 16)
    }
</script>

<div class="container-max-md">
    <Loadable promise={initPromise}>
    {#if user}
    <div class="page-summary-bar">
        <div>
            <h1>{user.username}</h1>
            <div class="text-muted">User</div>
        </div>
    </div>

    <FormGroup floating label="Username">
        <Input bind:value={user.username} />
    </FormGroup>

    <FormGroup floating label="Description">
        <Input bind:value={user.description} />
    </FormGroup>

    <CredentialEditor
        userId={user.id}
        username={user.username}
        bind:credentialPolicy={user.credentialPolicy!}
    />

    <h4 class="mt-4">User roles</h4>
    <div class="list-group list-group-flush mb-3">
        {#each allRoles as role (role.id)}
            {@const assignment = roleAssignments[role.id]}
            <div class="list-group-item">
                <div class="d-flex align-items-center">
                    <Input
                        id="role-{role.id}"
                        class="mb-0 me-2"
                        type="switch"
                        on:change={() => toggleRole(role)}
                        checked={!!assignment} />
                    <label for="role-{role.id}" class="flex-grow-1 mb-0">
                        <div class="d-flex align-items-center flex-wrap">
                            <span>{role.name}</span>
                            {#if assignment}
                                {#if assignment.isExpired}
                                    <Badge color="danger" class="ms-2">Expired</Badge>
                                {:else if assignment.expiresAt}
                                    <Badge color="warning" class="ms-2">Expires: {formatExpirationDate(assignment.expiresAt)}</Badge>
                                {:else}
                                    <Badge color="secondary" class="ms-2">Permanent</Badge>
                                {/if}
                                {#if assignment.allowFileTransfer === 'deny'}
                                    <Badge color="danger" class="ms-2">SFTP Denied</Badge>
                                {:else if assignment.allowFileTransfer === 'allow'}
                                    <Badge color="success" class="ms-2">SFTP Allowed</Badge>
                                {/if}
                            {/if}
                        </div>
                        {#if role.description}
                            <small class="text-muted">{role.description}</small>
                        {/if}
                    </label>
                </div>
                {#if assignment}
                    <div class="mt-2">
                        <div class="d-flex align-items-center mb-2">
                            <label class="me-2 text-nowrap" style="min-width: 80px;">Expiration:</label>
                            <Input
                                type="datetime-local"
                                style="max-width: 200px;"
                                value={toInputDatetime(assignment.expiresAt)}
                                on:change={(e) => {
                                    roleExpirationInputs[role.id] = e.currentTarget.value
                                }}
                                placeholder="Expiration (optional)"
                            />
                        </div>
                        <div class="d-flex align-items-center mb-2">
                            <label class="me-2 text-nowrap" style="min-width: 80px;">File Transfer:</label>
                            <select
                                class="form-select form-select-sm"
                                style="max-width: 200px;"
                                value={assignment.allowFileTransfer ?? ''}
                                on:change={(e) => {
                                    roleFileTransferInputs[role.id] = e.currentTarget.value || undefined
                                }}
                            >
                                <option value="">Allow (default)</option>
                                <option value="allow">Explicitly Allow</option>
                                <option value="deny">Deny</option>
                            </select>
                        </div>
                        <AsyncButton
                            color="secondary"
                            class="btn-sm"
                            click={() => updateRoleAssignment(role)}
                        >Update assignment</AsyncButton>
                    </div>
                {/if}
            </div>
        {/each}
    </div>

    <h4 class="mt-4">Traffic</h4>
    <FormGroup class="mb-5">
        <label for="rateLimitBytesPerSecond">Global bandwidth limit</label>
        <RateLimitInput
            id="rateLimitBytesPerSecond"
            bind:value={user.rateLimitBytesPerSecond}
        />
    </FormGroup>
    {/if}
    </Loadable>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    <div class="d-flex">
        <AsyncButton
        color="primary"
            class="ms-auto"
            click={update}
        >Update</AsyncButton>

        <AsyncButton
            class="ms-2"
            color="danger"
            click={remove}
        >Remove</AsyncButton>
    </div>
</div>
