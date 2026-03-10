<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	
	const dispatch = createEventDispatcher();
	
	export let partitions = [];
	export let currentPartition = '';
	
	function changePartition(partitionId: string) {
		dispatch('change', partitionId);
	}
</script>

<div class="partition-tabs">
	{#each partitions as partition}
		<button
			class="tab"
			class:active={partition.id === currentPartition}
			on:click={() => changePartition(partition.id)}
		>
			<span class="tab-icon">
				{partition.type === 'azure-kv' ? '🔐' : '🏠'}
			</span>
			<span class="tab-name">{partition.name}</span>
			<span class="tab-count">{partition.passwordCount}</span>
		</button>
	{/each}
	
	<button class="tab add-tab" title="Add new partition">
		<span class="tab-icon">➕</span>
		<span class="tab-name">Add Partition</span>
	</button>
</div>

<style>
	.partition-tabs {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-6);
		border-bottom: 1px solid var(--color-border);
		padding-bottom: var(--space-4);
	}
	
	.tab {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-4);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--border-radius-md);
		cursor: pointer;
		transition: all 0.2s ease;
		font-size: var(--font-size-sm);
	}
	
	.tab:hover {
		background: var(--color-surface-hover);
		border-color: var(--color-border-hover);
	}
	
	.tab.active {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}
	
	.tab-icon {
		font-size: var(--font-size-base);
	}
	
	.tab-name {
		font-weight: var(--font-weight-medium);
	}
	
	.tab-count {
		background: var(--color-background);
		color: var(--color-foreground);
		padding: var(--space-1) var(--space-2);
		border-radius: var(--border-radius-full);
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-bold);
		min-width: 20px;
		text-align: center;
	}
	
	.add-tab {
		opacity: 0.7;
		border-style: dashed;
	}
	
	.add-tab:hover {
		opacity: 1;
	}
</style>