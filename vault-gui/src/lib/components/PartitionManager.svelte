<!--
  PartitionManager – multi-partition management UI
  Shows all partitions with sync status and allows creating new ones.
-->
<script lang="ts">
	import type { PartitionData } from '$lib/api.js';
	import SecurityBadge from './SecurityBadge.svelte';

	interface Props {
		partitions?: PartitionData[];
		onswitch?: (id: string) => void;
		oncreate?: (partition: Omit<PartitionData, 'id' | 'passwordCount'>) => void;
	}

	let { partitions = [], onswitch, oncreate }: Props = $props();

	let showCreateForm = $state(false);
	let newName = $state('');
	let newType = $state<PartitionData['type']>('local');

	function handleCreate() {
		if (!newName.trim()) return;
		oncreate?.({ name: newName.trim(), type: newType });
		newName = '';
		newType = 'local';
		showCreateForm = false;
	}

	const typeInfo: Record<
		PartitionData['type'],
		{ icon: string; description: string; color: string }
	> = {
		local: {
			icon: '🏠',
			description: 'Local P2P sync – no cloud required. Free forever.',
			color: 'var(--color-partition-local)',
		},
		'azure-kv': {
			icon: '☁️',
			description: 'Azure Key Vault – enterprise compliance storage. Requires license.',
			color: 'var(--color-partition-azure)',
		},
		enterprise: {
			icon: '🏢',
			description: 'Managed enterprise partition with RBAC. Requires license.',
			color: 'var(--color-partition-enterprise)',
		},
	};
</script>

<section class="partition-manager" aria-label="Partition manager">
	<div class="manager-header">
		<div>
			<h2>Partitions</h2>
			<p class="subtitle">Manage your local and enterprise sync partitions.</p>
		</div>
		<button
			class="create-btn"
			onclick={() => (showCreateForm = !showCreateForm)}
			aria-expanded={showCreateForm}
		>
			{showCreateForm ? '✕ Cancel' : '+ New Partition'}
		</button>
	</div>

	<!-- Create partition form -->
	{#if showCreateForm}
		<div class="create-form" role="form" aria-label="New partition">
			<div class="form-row">
				<label for="partition-name" class="form-label">Name</label>
				<input
					id="partition-name"
					bind:value={newName}
					placeholder="e.g. Work, Personal, Dev"
					class="form-input"
					onkeydown={(e) => e.key === 'Enter' && handleCreate()}
				/>
			</div>

			<div class="form-row">
				<span class="form-label">Type</span>
				<div class="type-options" role="radiogroup" aria-label="Partition type">
					{#each Object.entries(typeInfo) as [type, info]}
						<label
							class="type-option"
							class:selected={newType === type}
							style="--type-color: {info.color}"
						>
							<input
								type="radio"
								name="partition-type"
								value={type}
								bind:group={newType}
								class="sr-only"
							/>
							<span class="type-icon" aria-hidden="true">{info.icon}</span>
							<div class="type-details">
								<span class="type-name"
									>{type === 'azure-kv' ? 'Azure KV' : type.charAt(0).toUpperCase() + type.slice(1)}</span
								>
								<span class="type-desc">{info.description}</span>
							</div>
						</label>
					{/each}
				</div>
			</div>

			<div class="form-actions">
				<button class="submit-btn" onclick={handleCreate} disabled={!newName.trim()}>
					Create Partition
				</button>
			</div>
		</div>
	{/if}

	<!-- Partition list -->
	{#if partitions.length === 0}
		<div class="empty-state">
			<span aria-hidden="true">📂</span>
			<p>No partitions yet. Create one above to get started.</p>
		</div>
	{:else}
		<div class="partition-list" role="list">
			{#each partitions as partition (partition.id)}
				{@const info = typeInfo[partition.type]}
				<div class="partition-card" role="listitem" style="--card-color: {info.color}">
					<div class="partition-card-left">
						<span class="partition-type-icon" aria-hidden="true">{info.icon}</span>
						<div class="partition-details">
							<span class="partition-card-name">{partition.name}</span>
							<span class="partition-card-type">{info.description}</span>
						</div>
					</div>

					<div class="partition-card-right">
						<SecurityBadge status="secure" label="{partition.passwordCount} passwords" />
						<button
							class="switch-btn"
							onclick={() => onswitch?.(partition.id)}
							aria-label="Switch to {partition.name} partition"
						>
							Open →
						</button>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</section>

<style>
	.partition-manager {
		display: flex;
		flex-direction: column;
		gap: var(--space-6);
	}

	.manager-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--space-4);
	}

	.manager-header h2 {
		margin: 0 0 var(--space-1) 0;
		font-size: var(--font-size-xl);
		font-weight: var(--font-weight-bold);
	}

	.subtitle {
		margin: 0;
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
	}

	.create-btn {
		padding: var(--space-2) var(--space-4);
		background: var(--color-primary);
		color: var(--color-primary-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		white-space: nowrap;
		transition: background-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.create-btn:hover {
		background: var(--color-primary-hover);
	}

	/* Create form */
	.create-form {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-6);
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
	}

	.form-row {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.form-label {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		color: var(--color-foreground-muted);
	}

	.form-input {
		padding: var(--space-3) var(--space-4);
		background: var(--color-surface-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-sans);
		outline: none;
		transition: border-color var(--transition-fast);
	}

	.form-input:focus {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-subtle);
	}

	.type-options {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.type-option {
		display: flex;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-3);
		border: 2px solid var(--color-border);
		border-radius: var(--radius-md);
		cursor: pointer;
		transition:
			border-color var(--transition-fast),
			background-color var(--transition-fast);
	}

	.type-option:hover {
		border-color: var(--type-color, var(--color-border-hover));
		background: var(--color-surface-hover);
	}

	.type-option.selected {
		border-color: var(--type-color, var(--color-primary));
		background: color-mix(in srgb, var(--type-color, var(--color-primary)) 8%, transparent);
	}

	.type-icon {
		font-size: 1.25rem;
		flex-shrink: 0;
	}

	.type-details {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.type-name {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		color: var(--color-foreground);
	}

	.type-desc {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
	}

	.form-actions {
		display: flex;
		justify-content: flex-end;
	}

	.submit-btn {
		padding: var(--space-3) var(--space-6);
		background: var(--color-success);
		color: var(--color-success-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		transition: background-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.submit-btn:hover:not(:disabled) {
		background: color-mix(in srgb, var(--color-success) 85%, black);
	}

	.submit-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	/* Partition list */
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-8);
		color: var(--color-foreground-muted);
		font-size: var(--font-size-sm);
		text-align: center;
	}

	.empty-state span {
		font-size: 2rem;
	}

	.partition-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.partition-card {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-4);
		padding: var(--space-4);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-left: 4px solid var(--card-color, var(--color-border));
		border-radius: var(--radius-lg);
		transition: box-shadow var(--transition-fast);
	}

	.partition-card:hover {
		box-shadow: var(--shadow-md);
	}

	.partition-card-left {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		min-width: 0;
	}

	.partition-type-icon {
		font-size: 1.5rem;
		flex-shrink: 0;
	}

	.partition-details {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		min-width: 0;
	}

	.partition-card-name {
		font-size: var(--font-size-base);
		font-weight: var(--font-weight-semibold);
		color: var(--color-foreground);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.partition-card-type {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
	}

	.partition-card-right {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		flex-shrink: 0;
	}

	.switch-btn {
		padding: var(--space-2) var(--space-4);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		cursor: pointer;
		white-space: nowrap;
		transition:
			background-color var(--transition-fast),
			border-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.switch-btn:hover {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}
</style>
