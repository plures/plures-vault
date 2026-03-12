<!--
  AuditLog – Praxis ledger UI
  Displays the in-memory audit trail captured by praxisState.
-->
<script lang="ts">
	import type { PraxisAction } from '$lib/praxis.js';
	import { formatActionLabel, formatRelativeTime } from '$lib/praxis.js';

	interface Props {
		entries?: PraxisAction[];
		maxVisible?: number;
	}

	let { entries = [], maxVisible = 50 }: Props = $props();

	let filterSeverity = $state<'all' | 'info' | 'warning' | 'critical'>('all');
	let filterText = $state('');

	const filtered = $derived(
		(() => {
			let result = entries;
			if (filterSeverity !== 'all') {
				result = result.filter((e) => e.severity === filterSeverity);
			}
			if (filterText.trim()) {
				const q = filterText.toLowerCase();
				result = result.filter(
					(e) =>
						e.action.toLowerCase().includes(q) ||
						e.credentialName?.toLowerCase().includes(q) ||
						e.partition?.toLowerCase().includes(q)
				);
			}
			return result.slice(0, maxVisible);
		})()
	);

	const severityIcon: Record<PraxisAction['severity'], string> = {
		info: '🔵',
		warning: '🟡',
		critical: '🔴',
	};

	const severityColor: Record<PraxisAction['severity'], string> = {
		info: 'var(--color-info)',
		warning: 'var(--color-warning)',
		critical: 'var(--color-destructive)',
	};
</script>

<section class="audit-log" aria-label="Praxis audit log">
	<div class="audit-header">
		<div class="audit-title">
			<h2>Praxis Audit Log</h2>
			<span class="entry-count">{entries.length} entries</span>
		</div>

		<div class="audit-filters">
			<input
				type="search"
				bind:value={filterText}
				placeholder="Filter actions…"
				class="filter-input"
				aria-label="Filter audit entries"
			/>

			<div class="severity-filters" role="group" aria-label="Filter by severity">
				{#each ['all', 'info', 'warning', 'critical'] as sev}
					<button
						class="sev-btn"
						class:active={filterSeverity === sev}
						onclick={() => (filterSeverity = sev as typeof filterSeverity)}
					>
						{sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
					</button>
				{/each}
			</div>
		</div>
	</div>

	{#if entries.length === 0}
		<div class="empty-state">
			<span aria-hidden="true">📋</span>
			<p>No audit entries yet. Actions will appear here as you use the vault.</p>
		</div>
	{:else if filtered.length === 0}
		<div class="empty-state">
			<span aria-hidden="true">🔍</span>
			<p>No entries match your filter.</p>
		</div>
	{:else}
		<ol class="entry-list" aria-label="Audit entries, newest first">
			{#each filtered as entry (entry.id)}
				<li
					class="entry"
					class:entry--warning={entry.severity === 'warning'}
					class:entry--critical={entry.severity === 'critical'}
					class:entry--failed={!entry.success}
				>
					<span
						class="entry-icon"
						aria-hidden="true"
						title={entry.severity}
					>{severityIcon[entry.severity]}</span>

					<div class="entry-body">
						<div class="entry-action">
							<span class="action-label">{formatActionLabel(entry.action)}</span>
							{#if !entry.success}
								<span class="failed-badge" aria-label="Failed">Failed</span>
							{/if}
						</div>

						<div class="entry-meta">
							{#if entry.credentialName}
								<span class="meta-item">🔑 {entry.credentialName}</span>
							{/if}
							{#if entry.partition}
								<span class="meta-item">📂 {entry.partition}</span>
							{/if}
							{#if entry.errorMessage}
								<span class="meta-item meta-item--error">⚠️ {entry.errorMessage}</span>
							{/if}
						</div>
					</div>

					<time
						class="entry-time"
						datetime={entry.timestamp}
						title={new Date(entry.timestamp).toLocaleString()}
					>
						{formatRelativeTime(entry.timestamp)}
					</time>
				</li>
			{/each}
		</ol>

		{#if entries.length > maxVisible}
			<p class="truncated-note">
				Showing newest {maxVisible} of {entries.length} entries.
			</p>
		{/if}
	{/if}
</section>

<style>
	.audit-log {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		height: 100%;
	}

	.audit-header {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.audit-title {
		display: flex;
		align-items: baseline;
		gap: var(--space-3);
	}

	.audit-title h2 {
		margin: 0;
		font-size: var(--font-size-xl);
		font-weight: var(--font-weight-bold);
	}

	.entry-count {
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
	}

	.audit-filters {
		display: flex;
		gap: var(--space-3);
		flex-wrap: wrap;
	}

	.filter-input {
		flex: 1;
		min-width: 180px;
		padding: var(--space-2) var(--space-3);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-sans);
		outline: none;
		transition: border-color var(--transition-fast);
	}

	.filter-input:focus {
		border-color: var(--color-primary);
	}

	.severity-filters {
		display: flex;
		gap: var(--space-1);
	}

	.sev-btn {
		padding: var(--space-1) var(--space-3);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-full);
		color: var(--color-foreground-muted);
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-medium);
		cursor: pointer;
		transition:
			background-color var(--transition-fast),
			color var(--transition-fast),
			border-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.sev-btn:hover {
		background: var(--color-surface-hover);
		color: var(--color-foreground);
	}

	.sev-btn.active {
		background: var(--color-primary);
		border-color: var(--color-primary);
		color: var(--color-primary-foreground);
	}

	.empty-state {
		flex: 1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-3);
		color: var(--color-foreground-muted);
		font-size: var(--font-size-sm);
		padding: var(--space-12);
		text-align: center;
	}

	.empty-state span {
		font-size: 2.5rem;
	}

	.entry-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		overflow-y: auto;
		flex: 1;
	}

	.entry {
		display: flex;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-3);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		transition: border-color var(--transition-fast);
	}

	.entry:hover {
		border-color: var(--color-border-hover);
	}

	.entry--warning {
		border-left: 3px solid var(--color-warning);
	}

	.entry--critical {
		border-left: 3px solid var(--color-destructive);
	}

	.entry--failed {
		opacity: 0.85;
	}

	.entry-icon {
		font-size: var(--font-size-sm);
		flex-shrink: 0;
		margin-top: 2px;
	}

	.entry-body {
		flex: 1;
		min-width: 0;
	}

	.entry-action {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-1);
	}

	.action-label {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		color: var(--color-foreground);
	}

	.failed-badge {
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-semibold);
		padding: 1px var(--space-2);
		background: var(--color-destructive-subtle);
		color: var(--color-destructive);
		border-radius: var(--radius-full);
	}

	.entry-meta {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}

	.meta-item {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
	}

	.meta-item--error {
		color: var(--color-destructive);
	}

	.entry-time {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		white-space: nowrap;
		flex-shrink: 0;
	}

	.truncated-note {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		text-align: center;
		margin: 0;
		padding: var(--space-2) 0;
	}
</style>
