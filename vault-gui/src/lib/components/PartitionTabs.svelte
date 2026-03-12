<script lang="ts">
	import type { PartitionData } from '$lib/api.js';

	interface Props {
		partitions?: PartitionData[];
		currentPartition?: string;
		onchange?: (partitionId: string) => void;
		onadd?: () => void;
	}

	let {
		partitions = [],
		currentPartition = '',
		onchange,
		onadd,
	}: Props = $props();
</script>

<div class="partition-tabs" role="tablist" aria-label="Vault partitions">
	{#each partitions as partition (partition.id)}
		<button
			role="tab"
			class="tab"
			class:active={partition.id === currentPartition}
			onclick={() => onchange?.(partition.id)}
			aria-selected={partition.id === currentPartition}
			aria-label="{partition.name} partition"
		>
			<span class="tab-icon" aria-hidden="true">
				{#if partition.type === 'azure-kv'}
					🔐
				{:else if partition.type === 'enterprise'}
					🏢
				{:else}
					🏠
				{/if}
			</span>
			<span class="tab-name">{partition.name}</span>
			<span class="tab-count" aria-label="{partition.passwordCount} passwords">
				{partition.passwordCount}
			</span>
		</button>
	{/each}

	<button
		class="tab add-tab"
		title="Add new partition"
		onclick={() => onadd?.()}
		aria-label="Add new partition"
	>
		<span class="tab-icon" aria-hidden="true">➕</span>
		<span class="tab-name">Add Partition</span>
	</button>
</div>

<style>
	.partition-tabs {
		display: flex;
		gap: var(--space-2);
		flex-wrap: wrap;
		padding-bottom: var(--space-4);
		border-bottom: 1px solid var(--color-border);
		margin-bottom: var(--space-6);
	}

	.tab {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-4);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground-muted);
		cursor: pointer;
		transition:
			background-color var(--transition-fast),
			border-color var(--transition-fast),
			color var(--transition-fast);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-sans);
	}

	.tab:hover {
		background: var(--color-surface-hover);
		border-color: var(--color-border-hover);
		color: var(--color-foreground);
	}

	.tab.active {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}

	.tab-icon {
		font-size: var(--font-size-sm);
	}

	.tab-name {
		font-weight: var(--font-weight-medium);
	}

	.tab-count {
		background: rgba(255, 255, 255, 0.15);
		padding: 1px var(--space-2);
		border-radius: var(--radius-full);
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-bold);
		min-width: 20px;
		text-align: center;
	}

	.tab:not(.active) .tab-count {
		background: var(--color-surface-hover);
		color: var(--color-foreground-muted);
	}

	.add-tab {
		border-style: dashed;
		opacity: 0.6;
	}

	.add-tab:hover {
		opacity: 1;
	}
</style>