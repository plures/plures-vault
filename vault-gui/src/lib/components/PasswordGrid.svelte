<script lang="ts">
	import { Button, Pane } from '@plures/design-dojo';
	
	export let passwords = [];
	
	function copyPassword(password: string) {
		// TODO: Integrate with Tauri clipboard API
		navigator.clipboard.writeText(password);
	}
	
	function editPassword(passwordId: string) {
		// TODO: Open edit dialog
		console.log('Edit password:', passwordId);
	}
	
	function deletePassword(passwordId: string) {
		// TODO: Implement deletion with confirmation
		console.log('Delete password:', passwordId);
	}
</script>

<div class="password-grid">
	{#each passwords as password}
		<Pane class="password-card">
			<div class="password-header">
				<div class="password-info">
					<h3 class="password-title">{password.title}</h3>
					<p class="password-url">{password.url}</p>
				</div>
				<div class="password-actions">
					<Button variant="ghost" size="sm" on:click={() => copyPassword('***')}>
						📋
					</Button>
					<Button variant="ghost" size="sm" on:click={() => editPassword(password.id)}>
						✏️
					</Button>
					<Button variant="ghost" size="sm" on:click={() => deletePassword(password.id)}>
						🗑️
					</Button>
				</div>
			</div>
			
			<div class="password-details">
				<div class="detail-row">
					<span class="detail-label">Username:</span>
					<span class="detail-value">{password.username}</span>
					<Button variant="ghost" size="xs" on:click={() => copyPassword(password.username)}>
						📋
					</Button>
				</div>
				
				<div class="detail-row">
					<span class="detail-label">Password:</span>
					<span class="detail-value">••••••••••••</span>
					<Button variant="ghost" size="xs" on:click={() => copyPassword('***')}>
						📋
					</Button>
				</div>
				
				<div class="detail-row">
					<span class="detail-label">URL:</span>
					<a href={`https://${password.url}`} target="_blank" class="detail-link">
						{password.url} ↗
					</a>
				</div>
			</div>
		</Pane>
	{:else}
		<div class="empty-state">
			<div class="empty-icon">🔒</div>
			<h3>No passwords found</h3>
			<p>Add your first password to get started</p>
			<Button variant="default">Add Password</Button>
		</div>
	{/each}
</div>

<style>
	.password-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
		gap: var(--space-4);
	}
	
	:global(.password-card) {
		padding: var(--space-4);
		border: 1px solid var(--color-border);
		border-radius: var(--border-radius-lg);
		background: var(--color-surface);
		transition: all 0.2s ease;
	}
	
	:global(.password-card:hover) {
		border-color: var(--color-border-hover);
		box-shadow: var(--shadow-md);
	}
	
	.password-header {
		display: flex;
		justify-content: space-between;
		align-items: flex-start;
		margin-bottom: var(--space-4);
	}
	
	.password-title {
		font-size: var(--font-size-lg);
		font-weight: var(--font-weight-bold);
		margin: 0 0 var(--space-1) 0;
		color: var(--color-foreground);
	}
	
	.password-url {
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
		margin: 0;
	}
	
	.password-actions {
		display: flex;
		gap: var(--space-1);
		opacity: 0.7;
		transition: opacity 0.2s ease;
	}
	
	:global(.password-card:hover) .password-actions {
		opacity: 1;
	}
	
	.password-details {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	
	.detail-row {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	
	.detail-label {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		font-weight: var(--font-weight-medium);
		min-width: 70px;
	}
	
	.detail-value {
		font-size: var(--font-size-sm);
		color: var(--color-foreground);
		flex: 1;
		font-family: var(--font-family-mono);
	}
	
	.detail-link {
		color: var(--color-primary);
		text-decoration: none;
		font-size: var(--font-size-sm);
		flex: 1;
	}
	
	.detail-link:hover {
		text-decoration: underline;
	}
	
	.empty-state {
		grid-column: 1 / -1;
		text-align: center;
		padding: var(--space-8);
		color: var(--color-foreground-muted);
	}
	
	.empty-icon {
		font-size: 4rem;
		margin-bottom: var(--space-4);
	}
	
	.empty-state h3 {
		font-size: var(--font-size-xl);
		font-weight: var(--font-weight-bold);
		margin: 0 0 var(--space-2) 0;
		color: var(--color-foreground);
	}
	
	.empty-state p {
		margin: 0 0 var(--space-4) 0;
	}
</style>