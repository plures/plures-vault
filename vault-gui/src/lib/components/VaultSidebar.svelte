<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button } from '@plures/design-dojo';
	
	const dispatch = createEventDispatcher();
	
	export let partitions = [];
	export let currentPartition = '';
	
	function selectPartition(partitionId: string) {
		dispatch('partition-change', partitionId);
	}
</script>

<nav class="sidebar">
	<div class="sidebar-header">
		<h1>Plures Vault</h1>
		<p class="subtitle">Zero-Trust Password Manager</p>
	</div>
	
	<div class="partitions-section">
		<h2>Partitions</h2>
		{#each partitions as partition}
			<button
				class="partition-item"
				class:active={partition.id === currentPartition}
				on:click={() => selectPartition(partition.id)}
			>
				<div class="partition-info">
					<span class="partition-name">{partition.name}</span>
					<span class="partition-type">{partition.type === 'azure-kv' ? '🔐 Azure KV' : '🏠 Local'}</span>
				</div>
				<span class="password-count">{partition.passwordCount}</span>
			</button>
		{/each}
	</div>
	
	<div class="sidebar-footer">
		<Button variant="outline" size="sm">Settings</Button>
		<Button variant="outline" size="sm">Lock Vault</Button>
	</div>
</nav>

<style>
	.sidebar {
		display: flex;
		flex-direction: column;
		height: 100%;
		background: var(--color-surface);
		border-right: 1px solid var(--color-border);
		padding: var(--space-4);
	}
	
	.sidebar-header h1 {
		font-size: var(--font-size-lg);
		font-weight: var(--font-weight-bold);
		margin: 0 0 var(--space-1) 0;
		color: var(--color-foreground);
	}
	
	.subtitle {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		margin: 0 0 var(--space-6) 0;
	}
	
	.partitions-section h2 {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		margin: 0 0 var(--space-3) 0;
		color: var(--color-foreground);
	}
	
	.partition-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		width: 100%;
		padding: var(--space-3);
		margin-bottom: var(--space-2);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--border-radius-md);
		cursor: pointer;
		transition: all 0.2s ease;
	}
	
	.partition-item:hover {
		background: var(--color-surface-hover);
	}
	
	.partition-item.active {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}
	
	.partition-info {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
	}
	
	.partition-name {
		font-weight: var(--font-weight-medium);
		font-size: var(--font-size-sm);
	}
	
	.partition-type {
		font-size: var(--font-size-xs);
		opacity: 0.7;
	}
	
	.password-count {
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-bold);
		background: var(--color-background);
		padding: var(--space-1) var(--space-2);
		border-radius: var(--border-radius-full);
	}
	
	.sidebar-footer {
		margin-top: auto;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
</style>