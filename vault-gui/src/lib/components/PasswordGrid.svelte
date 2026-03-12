<script lang="ts">
	import type { CredentialData } from '$lib/api.js';

	interface Props {
		credentials?: CredentialData[];
		onadd?: () => void;
		onedit?: (id: string) => void;
		ondelete?: (id: string) => void;
		oncopypassword?: (id: string, name: string) => void;
		oncopyusername?: (id: string, name: string) => void;
	}

	let {
		credentials = [],
		onadd,
		onedit,
		ondelete,
		oncopypassword,
		oncopyusername,
	}: Props = $props();

	let visiblePasswords = $state<Set<string>>(new Set());

	function togglePasswordVisibility(id: string) {
		const next = new Set(visiblePasswords);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		visiblePasswords = next;
	}
</script>

<div class="password-grid" role="list" aria-label="Credentials">
	{#each credentials as credential (credential.id)}
		{@const showPw = visiblePasswords.has(credential.id ?? '')}
		<article class="password-card" role="listitem">
			<div class="card-header">
				<div class="card-title-group">
					<div class="card-favicon" aria-hidden="true">
						{#if credential.url}
							<img
								src="https://www.google.com/s2/favicons?sz=32&domain={credential.url}"
								alt=""
								width="20"
								height="20"
								onerror={(e) => {
									(e.currentTarget as HTMLImageElement).style.display = 'none';
								}}
							/>
						{:else}
							🔑
						{/if}
					</div>
					<div>
						<h3 class="card-name">{credential.name}</h3>
						{#if credential.url}
							<a
								href={credential.url.startsWith('http')
									? credential.url
									: `https://${credential.url}`}
								target="_blank"
								rel="noopener noreferrer"
								class="card-url"
							>
								{credential.url}
							</a>
						{/if}
					</div>
				</div>

				<div class="card-actions">
					<button
						class="action-btn"
						onclick={() => oncopyusername?.(credential.id!, credential.name)}
						title="Copy username"
						aria-label="Copy username for {credential.name}"
					>
						👤
					</button>
					<button
						class="action-btn"
						onclick={() => oncopypassword?.(credential.id!, credential.name)}
						title="Copy password"
						aria-label="Copy password for {credential.name}"
					>
						📋
					</button>
					<button
						class="action-btn"
						onclick={() => onedit?.(credential.id!)}
						title="Edit credential"
						aria-label="Edit {credential.name}"
					>
						✏️
					</button>
					<button
						class="action-btn action-btn--danger"
						onclick={() => ondelete?.(credential.id!)}
						title="Delete credential"
						aria-label="Delete {credential.name}"
					>
						🗑️
					</button>
				</div>
			</div>

			<div class="card-body">
				<div class="field-row">
					<span class="field-label">Username</span>
					<span class="field-value">{credential.username}</span>
				</div>

				<div class="field-row">
					<span class="field-label">Password</span>
					<span class="field-value field-value--mono">
						{showPw ? credential.password : '••••••••••••'}
					</span>
					<button
						class="action-btn action-btn--sm"
						onclick={() => togglePasswordVisibility(credential.id ?? '')}
						aria-label={showPw ? 'Hide password' : 'Reveal password'}
					>
						{showPw ? '🙈' : '👁️'}
					</button>
				</div>
			</div>
		</article>
	{:else}
		<div class="empty-state">
			<div class="empty-icon" aria-hidden="true">🔒</div>
			<h3>No credentials yet</h3>
			<p>Add your first password to get started.</p>
			<button class="add-btn" onclick={() => onadd?.()}>Add Credential</button>
		</div>
	{/each}
</div>

<style>
	.password-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
		gap: var(--space-4);
	}

	.password-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		padding: var(--space-4);
		transition:
			border-color var(--transition-fast),
			box-shadow var(--transition-fast);
	}

	.password-card:hover {
		border-color: var(--color-border-hover);
		box-shadow: var(--shadow-md);
	}

	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		gap: var(--space-3);
		margin-bottom: var(--space-4);
	}

	.card-title-group {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		min-width: 0;
	}

	.card-favicon {
		font-size: 1.25rem;
		flex-shrink: 0;
	}

	.card-name {
		margin: 0;
		font-size: var(--font-size-base);
		font-weight: var(--font-weight-semibold);
		color: var(--color-foreground);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.card-url {
		display: block;
		font-size: var(--font-size-xs);
		color: var(--color-primary);
		text-decoration: none;
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.card-url:hover {
		text-decoration: underline;
	}

	.card-actions {
		display: flex;
		gap: var(--space-1);
		flex-shrink: 0;
		opacity: 0;
		transition: opacity var(--transition-fast);
	}

	.password-card:hover .card-actions,
	.password-card:focus-within .card-actions {
		opacity: 1;
	}

	.action-btn {
		background: transparent;
		border: none;
		color: var(--color-foreground-muted);
		cursor: pointer;
		padding: var(--space-1);
		border-radius: var(--radius-sm);
		font-size: var(--font-size-sm);
		transition: color var(--transition-fast), background-color var(--transition-fast);
		line-height: 1;
	}

	.action-btn:hover {
		color: var(--color-foreground);
		background: var(--color-surface-hover);
	}

	.action-btn--danger:hover {
		color: var(--color-destructive);
	}

	.action-btn--sm {
		font-size: var(--font-size-xs);
	}

	.card-body {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.field-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.field-label {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		font-weight: var(--font-weight-medium);
		min-width: 70px;
		flex-shrink: 0;
	}

	.field-value {
		font-size: var(--font-size-sm);
		color: var(--color-foreground);
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.field-value--mono {
		font-family: var(--font-family-mono);
		letter-spacing: 0.04em;
	}

	.empty-state {
		grid-column: 1 / -1;
		text-align: center;
		padding: var(--space-12);
		color: var(--color-foreground-muted);
	}

	.empty-icon {
		font-size: 3rem;
		margin-bottom: var(--space-4);
	}

	.empty-state h3 {
		font-size: var(--font-size-xl);
		font-weight: var(--font-weight-bold);
		margin: 0 0 var(--space-2) 0;
		color: var(--color-foreground);
	}

	.empty-state p {
		margin: 0 0 var(--space-6) 0;
	}

	.add-btn {
		padding: var(--space-3) var(--space-6);
		background: var(--color-success);
		color: var(--color-success-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		transition: background-color var(--transition-fast);
	}

	.add-btn:hover {
		background: color-mix(in srgb, var(--color-success) 85%, black);
	}
</style>