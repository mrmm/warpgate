<script lang="ts">
    import { api, BootstrapThemeColor, type TargetGroup, type Role } from 'admin/lib/api'
    import { Button, FormGroup, Input, Label, Alert } from '@sveltestrap/sveltestrap'
    import { stringifyError } from 'common/errors'
    import { VALID_CHOICES } from './common'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import AsyncButton from 'common/AsyncButton.svelte'
    import Loadable from 'common/Loadable.svelte'
    import { replace } from 'svelte-spa-router'

    interface Props {
        params: { id: string };
    }

    let { params }: Props = $props()
    let groupId = params.id

    let group: TargetGroup | undefined = $state()
    let error: string | undefined = $state()
    let saving = $state(false)

    let name = $state('')
    let description = $state('')
    let color = $state<BootstrapThemeColor | ''>('')

    let allRoles: Role[] = $state([])
    let roleIsAllowed: Record<string, boolean> = $state({})

    const initPromise = init()

    async function init () {
        try {
            group = await api.getTargetGroup({ id: groupId })
            name = group.name
            description = group.description
            color = group.color ?? ''
        } catch (e) {
            error = await stringifyError(e)
            throw e
        }
    }

    async function loadRoles () {
        allRoles = await api.getRoles()
        const groupRoles = await api.getTargetGroupRoles({ id: groupId })
        roleIsAllowed = Object.fromEntries(groupRoles.map(r => [r.id, true]))
        return allRoles
    }

    async function update () {
        if (!group) {
            return
        }

        saving = true
        error = undefined

        try {
            await api.updateTargetGroup({
                id: groupId,
                targetGroupDataRequest: {
                    name,
                    description: description || undefined,
                    color: color || undefined,
                },
            })
        } catch (e) {
            error = await stringifyError(e)
            throw e
        } finally {
            saving = false
        }
    }

    async function remove () {
        if (!group || !confirm(`Delete target group "${group.name}"?`)) {
            return
        }

        try {
            await api.deleteTargetGroup({ id: groupId })
            // Redirect to groups list
            replace('/config/target-groups')
        } catch (e) {
            error = await stringifyError(e)
            throw e
        }
    }

    async function toggleRole (role: Role) {
        error = undefined
        try {
            if (roleIsAllowed[role.id]) {
                await api.deleteTargetGroupRole({
                    id: groupId,
                    roleId: role.id,
                })
                roleIsAllowed = { ...roleIsAllowed, [role.id]: false }
            } else {
                await api.addTargetGroupRole({
                    id: groupId,
                    roleId: role.id,
                })
                roleIsAllowed = { ...roleIsAllowed, [role.id]: true }
            }
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>


{#if error}
    <Alert color="danger">{error}</Alert>
{/if}
<Loadable promise={initPromise}>
{#if group}
    <div class="container-max-md">
        <div class="page-summary-bar">
            <div>
                <h1>{group.name}</h1>
                <div class="text-muted">Target group</div>
            </div>
        </div>

        <form onsubmit={e => {
            e.preventDefault()
            update()
        }}>
            <FormGroup>
                <Label for="name">Name</Label>
                <Input
                    id="name"
                    bind:value={name}
                    required
                    disabled={saving}
                />
            </FormGroup>

            <FormGroup>
                <Label for="description">Description</Label>
                <Input
                    id="description"
                    type="textarea"
                    bind:value={description}
                    disabled={saving}
                />
            </FormGroup>

            <FormGroup>
                <Label for="color">Color</Label>
                <small class="form-text text-muted">
                    Optional Bootstrap theme color for visual organization
                </small>
                <div class="color-picker">
                    {#each VALID_CHOICES as value (value)}
                        <button
                            type="button"
                            class="btn btn-secondary gap-2 d-flex align-items-center"
                            class:active={color === value}
                            disabled={saving}
                            onclick={(e) => {
                                e.preventDefault()
                                color = value
                            }}
                            title={value || 'None'}
                        >
                            <GroupColorCircle color={value} />
                            <span>{value || 'None'}</span>
                        </button>
                    {/each}
                </div>
            </FormGroup>

            <div class="d-flex gap-2 mt-5">
                <AsyncButton click={update} color="primary">Update</AsyncButton>
                <Button color="danger" onclick={remove}>Remove</Button>
            </div>
        </form>

        <h4 class="mt-5">Roles with access to all targets in this group</h4>
        <p class="text-muted">Roles assigned here will have access to all targets in this group.</p>
        <Loadable promise={loadRoles()}>
            {#snippet children(roles)}
                <div class="list-group list-group-flush mb-3">
                    {#each roles as role (role.id)}
                        <label
                            for="group-role-{role.id}"
                            class="list-group-item list-group-item-action d-flex align-items-center"
                        >
                            <Input
                                id="group-role-{role.id}"
                                class="mb-0 me-2"
                                type="switch"
                                on:change={() => toggleRole(role)}
                                checked={roleIsAllowed[role.id]} />
                            <div>
                                <div>{role.name}</div>
                                {#if role.description}
                                    <small class="text-muted">{role.description}</small>
                                {/if}
                            </div>
                        </label>
                    {/each}
                </div>
            {/snippet}
        </Loadable>
    </div>
{/if}
</Loadable>

<style lang="scss">
    .color-picker {
        display: flex;
        flex-wrap: wrap;
        gap: 0.5rem;
    }
</style>
