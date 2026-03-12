<script lang="ts">
	import type { PartitionData } from '$lib/api.js';

	interface Props {
		partitions?: PartitionData[];
		currentPartition?: string;
		vaultName?: string;
		activeView?: 'passwords' | 'audit' | 'settings';
		onpartitionchange?: (id: string) => void;
		onlock?: () => void;
		onviewchange?: (view: 'passwords' | 'audit' | 'settings') => void;
	}

	let {
		partitions = [],
		currentPartition = '',
		vaultName,
		activeView = 'passwords',
		onpartitionchange,
		onlock,
		onviewchange,
	}: Props = $props();
</script>

<nav class="sidebar" aria-label="Vault navigation">
	<div class="sidebar-header">
		<div class="brand">
			<span class="brand-icon" aria-hidden="true">🔐</span>
			<div>
				<h1>Plures Vault</h1>
				{#if vaultName}
					<p class="vault-name">{vaultName}</p>
				{/if}
			</div>
		</div>
	</div>

	<!-- Navigation views -->
	<div class="nav-section">
		<button
			class="nav-item"
			class:nav-item--active={activeView === 'passwords'}
			onclick={() => onviewchange?.('passwords')}
			aria-current={activeView === 'passwords' ? 'page' : undefined}
		>
			<span aria-hidden="true">🔑</span>
			Passwords
		</button>
		<button
			class="nav-item"
			class:nav-item--active={activeView === 'audit'}
			onclick={() => onviewchange?.('audit')}
			aria-current={activeView === 'audit' ? 'page' : undefined}
		>
			<span aria-hidden="true">📋</span>
			Audit Log
		</button>
		<button
			class="nav-item"
			class:nav-item--active={activeView === 'settings'}
			onclick={() => onviewchange?.('settings')}
			aria-current={activeView === 'settings' ? 'page' : undefined}
		>
			<span aria-hidden="true">⚙️</span>
			Settings
		</button>
	</div>

	<!-- Partitions -->
	<div class="partitions-section">
		<h2 class="section-label">Partitions</h2>
		{#each partitions as partition (partition.id)}
			<button
				class="partition-item"
				class:partition-item--active={partition.id === currentPartition}
				onclick={() => onpartitionchange?.(partition.id)}
				aria-label="{partition.name} partition ({partition.passwordCount} passwords)"
			>
				<div class="partition-info">
					<span class="partition-name">{partition.name}</span>
					<span
						class="partition-badge"
						data-type={partition.type}
					>
						{#if partition.type === 'azure-kv'}
							Azure KV
						{:else if partition.type === 'enterprise'}
							Enterprise
						{:else}
							Local P2P
						{/if}
					</span>
				</div>
				<span class="partition-count">{partition.passwordCount}</span>
			</button>
		{/each}
	</div>

	<div class="sidebar-footer">
		<button class="lock-btn" onclick={() => onlock?.()}>
			<span aria-hidden="true">🔒</span>
			Lock Vault
		</button>
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
		overflow-y: auto;
	}

	.sidebar-header {
		margin-bottom: var(--space-6);
	}

	.brand {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}

	.brand-icon {
		font-size: 1.75rem;
		flex-shrink: 0;
	}

	.brand h1 {
		font-size: var(--font-size-base);
		font-weight: var(--font-weight-bold);
		margin: 0;
		color: var(--color-foreground);
	}

	.vault-name {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		margin: 0;
	}

	/* Nav section */
	.nav-section {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-6);
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-2) var(--space-3);
		background: transparent;
		border: none;
		border-radius: var(--radius-md);
		color: var(--color-foreground-muted);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		cursor: pointer;
		text-align: left;
		transition:
			background-color var(--transition-fast),
			color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.nav-item:hover {
		background: var(--color-surface-hover);
		color: var(--color-foreground);
	}

	.nav-item--active {
		background: var(--color-primary-subtle);
		color: var(--color-primary);
	}

	/* Partitions */
	.partitions-section {
		flex: 1;
	}

	.section-label {
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-semibold);
		color: var(--color-foreground-muted);
		text-transform: uppercase;
		letter-spacing: 0.08em;
		margin: 0 0 var(--space-2) 0;
	}

	.partition-item {
		display: flex;
		align-items: center;
		justify-content: space-between;
		width: 100%;
		padding: var(--space-3);
		margin-bottom: var(--space-1);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		cursor: pointer;
		transition:
			background-color var(--transition-fast),
			border-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.partition-item:hover {
		background: var(--color-surface-hover);
		border-color: var(--color-border-hover);
	}

	.partition-item--active {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}

	.partition-info {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-1);
	}

	.partition-name {
		font-weight: var(--font-weight-medium);
		font-size: var(--font-size-sm);
	}

	.partition-badge {
		font-size: var(--font-size-xs);
		opacity: 0.75;
	}

	.partition-badge[data-type='azure-kv'] {
		color: var(--color-partition-azure);
	}

	.partition-badge[data-type='enterprise'] {
		color: var(--color-partition-enterprise);
	}

	.partition-item--active .partition-badge {
		color: rgba(255, 255, 255, 0.75);
	}

	.partition-count {
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-bold);
		background: rgba(0, 0, 0, 0.2);
		padding: 2px var(--space-2);
		border-radius: var(--radius-full);
		min-width: 24px;
		text-align: center;
	}

	.sidebar-footer {
		padding-top: var(--space-4);
		border-top: 1px solid var(--color-border);
		margin-top: var(--space-4);
	}

	.lock-btn {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-3);
		background: var(--color-destructive-subtle);
		border: 1px solid transparent;
		border-radius: var(--radius-md);
		color: var(--color-destructive);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		transition:
			background-color var(--transition-fast),
			border-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.lock-btn:hover {
		background: var(--color-destructive);
		color: var(--color-destructive-foreground);
	}
</style>