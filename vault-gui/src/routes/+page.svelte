<script lang="ts">
	import { onMount } from 'svelte';
	import { vaultAPI, type CredentialData, type VaultStatus } from '$lib/api';
	
	let vaultStatus: VaultStatus | null = null;
	let isLoading = false;
	let errorMessage = '';
	let currentPartition = 'personal';
	let searchQuery = '';
	let masterPassword = '';
	let credentials: CredentialData[] = [];
	let showAddDialog = false;
	let newCredential: CredentialData = {
		name: '',
		username: '',
		password: '',
		url: '',
		notes: ''
	};
	
	// Mock partitions for demo - will be dynamic in Phase 3
	let partitions = [
		{ id: 'personal', name: 'Personal', type: 'local', passwordCount: 0 }
	];
	
	onMount(async () => {
		await checkVaultStatus();
	});
	
	async function checkVaultStatus() {
		try {
			isLoading = true;
			vaultStatus = await vaultAPI.checkStatus();
			if (vaultStatus.unlocked) {
				await loadCredentials();
			}
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Unknown error';
		} finally {
			isLoading = false;
		}
	}
	
	async function handleUnlock() {
		if (!masterPassword.trim()) return;
		
		try {
			isLoading = true;
			errorMessage = '';
			
			if (!vaultStatus?.initialized) {
				// Initialize new vault
				await vaultAPI.initialize('My Vault', masterPassword);
			} else {
				// Unlock existing vault
				await vaultAPI.unlock(masterPassword);
			}
			
			await loadCredentials();
			vaultStatus = { ...vaultStatus!, unlocked: true };
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to unlock vault';
		} finally {
			isLoading = false;
		}
	}
	
	async function loadCredentials() {
		try {
			credentials = await vaultAPI.listCredentials();
			// Update partition count
			partitions[0].passwordCount = credentials.length;
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to load credentials';
		}
	}
	
	async function handleAddCredential() {
		if (!newCredential.name.trim() || !newCredential.username.trim()) return;
		
		try {
			isLoading = true;
			await vaultAPI.addCredential(newCredential);
			await loadCredentials();
			
			// Reset form
			newCredential = { name: '', username: '', password: '', url: '', notes: '' };
			showAddDialog = false;
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to add credential';
		} finally {
			isLoading = false;
		}
	}
	
	async function handleDeleteCredential(credentialId: string) {
		if (!confirm('Are you sure you want to delete this credential?')) return;
		
		try {
			isLoading = true;
			await vaultAPI.deleteCredential(credentialId);
			await loadCredentials();
		} catch (error) {
			errorMessage = error instanceof Error ? error.message : 'Failed to delete credential';
		} finally {
			isLoading = false;
		}
	}
	
	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
		} catch (error) {
			console.warn('Failed to copy to clipboard:', error);
		}
	}
	
	function handlePartitionChange(partition: string) {
		currentPartition = partition;
	}
	
	$: filteredCredentials = credentials.filter(c => 
		c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
		c.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
		(c.url && c.url.toLowerCase().includes(searchQuery.toLowerCase()))
	);
</script>

<main class="vault-container">
	{#if isLoading}
		<div class="loading-screen">
			<div class="spinner"></div>
			<p>Loading...</p>
		</div>
	{:else if !vaultStatus?.unlocked}
		<div class="unlock-screen">
			<div class="unlock-dialog">
				<h1>🔐 Plures Vault</h1>
				{#if vaultStatus?.initialized}
					<p>Enter your master password to unlock your vault</p>
				{:else}
					<p>Initialize your new vault with a master password</p>
				{/if}
				
				{#if errorMessage}
					<div class="error-message">{errorMessage}</div>
				{/if}
				
				<input
					bind:value={masterPassword}
					type="password"
					placeholder="Master password"
					class="password-input"
					on:keydown={(e) => e.key === 'Enter' && handleUnlock()}
				/>
				
				<button 
					class="unlock-btn" 
					on:click={handleUnlock} 
					disabled={!masterPassword.trim()}
				>
					{vaultStatus?.initialized ? 'Unlock Vault' : 'Create Vault'}
				</button>
				
				<p class="security-note">
					<strong>Zero-knowledge security:</strong> Your master password never leaves this device.
				</p>
			</div>
		</div>
	{:else}
		<div class="vault-sidebar">
			<div class="sidebar-header">
				<h1>Plures Vault</h1>
				<p>Zero-Trust Password Manager</p>
				{#if vaultStatus.vault_name}
					<p class="vault-name">📁 {vaultStatus.vault_name}</p>
				{/if}
			</div>
			
			<div class="partitions">
				<h3>Partitions</h3>
				{#each partitions as partition}
					<button
						class="partition-btn"
						class:active={partition.id === currentPartition}
						on:click={() => handlePartitionChange(partition.id)}
					>
						<div>
							<div class="partition-name">{partition.name}</div>
							<div class="partition-type">🏠 Local</div>
						</div>
						<span class="count">{partition.passwordCount}</span>
					</button>
				{/each}
			</div>
			
			<div class="sidebar-actions">
				<button class="lock-btn" on:click={() => vaultAPI.lock().then(() => location.reload())}>
					🔒 Lock Vault
				</button>
			</div>
		</div>
		
		<div class="vault-main">
			<div class="toolbar">
				<input
					bind:value={searchQuery}
					placeholder="Search passwords..."
					class="search-input"
				/>
				<button class="add-btn" on:click={() => showAddDialog = true}>
					+ Add Password
				</button>
			</div>
			
			{#if errorMessage}
				<div class="error-banner">{errorMessage}</div>
			{/if}
			
			<div class="passwords-grid">
				{#each filteredCredentials as credential}
					<div class="password-card">
						<div class="card-header">
							<h3>{credential.name}</h3>
							<div class="actions">
								<button on:click={() => copyToClipboard(credential.username)} title="Copy username">
									👤
								</button>
								<button on:click={() => copyToClipboard(credential.password)} title="Copy password">
									🔑
								</button>
								<button on:click={() => handleDeleteCredential(credential.id!)} title="Delete">
									🗑️
								</button>
							</div>
						</div>
						<div class="card-body">
							<div class="field">
								<label>Username:</label>
								<span>{credential.username}</span>
							</div>
							<div class="field">
								<label>Password:</label>
								<span>••••••••••••</span>
							</div>
							{#if credential.url}
								<div class="field">
									<label>URL:</label>
									<a href={credential.url.startsWith('http') ? credential.url : `https://${credential.url}`} 
									   target="_blank" rel="noopener">
										{credential.url}
									</a>
								</div>
							{/if}
						</div>
					</div>
				{:else}
					<div class="empty-state">
						<h3>No passwords found</h3>
						<p>Add your first password to get started</p>
						<button class="add-btn" on:click={() => showAddDialog = true}>
							Add Password
						</button>
					</div>
				{/each}
			</div>
		</div>
	{/if}
	
	<!-- Add Credential Dialog -->
	{#if showAddDialog}
		<div class="modal-backdrop" on:click={() => showAddDialog = false}>
			<div class="modal-content" on:click|stopPropagation>
				<div class="modal-header">
					<h3>Add New Credential</h3>
					<button class="close-btn" on:click={() => showAddDialog = false}>×</button>
				</div>
				<div class="modal-body">
					<div class="form-group">
						<label for="name">Name *</label>
						<input id="name" bind:value={newCredential.name} placeholder="e.g. GitHub" />
					</div>
					<div class="form-group">
						<label for="username">Username *</label>
						<input id="username" bind:value={newCredential.username} placeholder="username or email" />
					</div>
					<div class="form-group">
						<label for="password">Password *</label>
						<input id="password" type="password" bind:value={newCredential.password} placeholder="password" />
					</div>
					<div class="form-group">
						<label for="url">URL</label>
						<input id="url" bind:value={newCredential.url} placeholder="https://example.com" />
					</div>
					<div class="form-group">
						<label for="notes">Notes</label>
						<textarea id="notes" bind:value={newCredential.notes} placeholder="Optional notes"></textarea>
					</div>
				</div>
				<div class="modal-footer">
					<button class="cancel-btn" on:click={() => showAddDialog = false}>Cancel</button>
					<button 
						class="save-btn" 
						on:click={handleAddCredential}
						disabled={!newCredential.name.trim() || !newCredential.username.trim()}
					>
						Add Credential
					</button>
				</div>
			</div>
		</div>
	{/if}
</main>

<style>
	.vault-container {
		display: grid;
		grid-template-columns: 250px 1fr;
		height: 100vh;
		background: #0a0a0a;
		color: #ffffff;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
	}
	
	.unlock-screen {
		grid-column: 1 / -1;
		display: flex;
		align-items: center;
		justify-content: center;
		background: #0a0a0a;
	}
	
	.unlock-dialog {
		background: #1a1a1a;
		padding: 2rem;
		border-radius: 12px;
		border: 1px solid #333;
		max-width: 400px;
		text-align: center;
	}
	
	.unlock-dialog h1 {
		margin: 0 0 0.5rem 0;
		font-size: 1.5rem;
	}
	
	.password-input {
		width: 100%;
		padding: 0.75rem;
		background: #2a2a2a;
		border: 1px solid #444;
		border-radius: 6px;
		color: white;
		margin: 1rem 0;
	}
	
	.unlock-btn {
		width: 100%;
		padding: 0.75rem;
		background: #3b82f6;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		margin-bottom: 1rem;
	}
	
	.unlock-btn:disabled {
		background: #555;
		cursor: not-allowed;
	}
	
	.security-note {
		font-size: 0.8rem;
		color: #888;
		margin: 0;
	}
	
	.vault-sidebar {
		background: #1a1a1a;
		border-right: 1px solid #333;
		padding: 1rem;
	}
	
	.sidebar-header h1 {
		margin: 0 0 0.25rem 0;
		font-size: 1.2rem;
	}
	
	.sidebar-header p {
		margin: 0 0 2rem 0;
		font-size: 0.8rem;
		color: #888;
	}
	
	.partitions h3 {
		margin: 0 0 1rem 0;
		font-size: 0.9rem;
		color: #ccc;
	}
	
	.partition-btn {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 0.75rem;
		background: transparent;
		border: 1px solid #333;
		border-radius: 6px;
		color: white;
		cursor: pointer;
		margin-bottom: 0.5rem;
		transition: all 0.2s;
	}
	
	.partition-btn:hover {
		background: #2a2a2a;
	}
	
	.partition-btn.active {
		background: #3b82f6;
		border-color: #3b82f6;
	}
	
	.partition-name {
		font-weight: 600;
		font-size: 0.9rem;
	}
	
	.partition-type {
		font-size: 0.7rem;
		opacity: 0.7;
	}
	
	.count {
		background: #333;
		padding: 0.25rem 0.5rem;
		border-radius: 12px;
		font-size: 0.7rem;
		font-weight: bold;
	}
	
	.vault-main {
		padding: 1.5rem;
		overflow-y: auto;
	}
	
	.toolbar {
		display: flex;
		gap: 1rem;
		margin-bottom: 2rem;
	}
	
	.search-input {
		flex: 1;
		padding: 0.75rem;
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 6px;
		color: white;
	}
	
	.add-btn {
		padding: 0.75rem 1.5rem;
		background: #10b981;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		font-weight: 600;
	}
	
	.passwords-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
		gap: 1rem;
	}
	
	.password-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 8px;
		padding: 1rem;
		transition: border-color 0.2s;
	}
	
	.password-card:hover {
		border-color: #555;
	}
	
	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}
	
	.card-header h3 {
		margin: 0;
		font-size: 1.1rem;
	}
	
	.actions {
		display: flex;
		gap: 0.5rem;
	}
	
	.actions button {
		background: transparent;
		border: none;
		color: #888;
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: color 0.2s;
	}
	
	.actions button:hover {
		color: white;
	}
	
	.card-body {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	
	.field {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	
	.field label {
		font-size: 0.8rem;
		color: #888;
		min-width: 80px;
	}
	
	.field span {
		font-family: 'Monaco', 'Menlo', monospace;
		font-size: 0.9rem;
	}
	
	.field a {
		color: #3b82f6;
		text-decoration: none;
	}
	
	.field a:hover {
		text-decoration: underline;
	}
	
	.empty-state {
		grid-column: 1 / -1;
		text-align: center;
		padding: 3rem;
		color: #888;
	}
	
	.empty-state h3 {
		margin: 0 0 0.5rem 0;
		color: white;
	}
	
	.empty-state p {
		margin: 0 0 1rem 0;
	}
	
	/* Loading and Error States */
	.loading-screen {
		grid-column: 1 / -1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		background: #0a0a0a;
		gap: 1rem;
	}
	
	.spinner {
		width: 40px;
		height: 40px;
		border: 3px solid #333;
		border-top: 3px solid #3b82f6;
		border-radius: 50%;
		animation: spin 1s linear infinite;
	}
	
	@keyframes spin {
		0% { transform: rotate(0deg); }
		100% { transform: rotate(360deg); }
	}
	
	.error-message {
		background: #dc2626;
		color: white;
		padding: 0.75rem;
		border-radius: 6px;
		margin: 1rem 0;
		font-size: 0.9rem;
	}
	
	.error-banner {
		background: #dc2626;
		color: white;
		padding: 0.75rem;
		border-radius: 6px;
		margin-bottom: 1rem;
	}
	
	/* Vault Name Display */
	.vault-name {
		font-size: 0.8rem;
		color: #888;
		margin-top: 0.5rem;
	}
	
	/* Sidebar Actions */
	.sidebar-actions {
		margin-top: auto;
		padding-top: 2rem;
	}
	
	.lock-btn {
		width: 100%;
		padding: 0.75rem;
		background: #dc2626;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		font-weight: 600;
		transition: background-color 0.2s;
	}
	
	.lock-btn:hover {
		background: #b91c1c;
	}
	
	/* Modal Styles */
	.modal-backdrop {
		position: fixed;
		top: 0;
		left: 0;
		width: 100vw;
		height: 100vh;
		background: rgba(0, 0, 0, 0.7);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	
	.modal-content {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 12px;
		min-width: 500px;
		max-width: 90vw;
		max-height: 90vh;
		overflow-y: auto;
	}
	
	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: 1.5rem 1.5rem 0 1.5rem;
	}
	
	.modal-header h3 {
		margin: 0;
		font-size: 1.2rem;
	}
	
	.close-btn {
		background: transparent;
		border: none;
		color: #888;
		font-size: 1.5rem;
		cursor: pointer;
		padding: 0;
		width: 30px;
		height: 30px;
		display: flex;
		align-items: center;
		justify-content: center;
		border-radius: 4px;
		transition: color 0.2s;
	}
	
	.close-btn:hover {
		color: white;
	}
	
	.modal-body {
		padding: 1.5rem;
	}
	
	.form-group {
		margin-bottom: 1rem;
	}
	
	.form-group label {
		display: block;
		margin-bottom: 0.5rem;
		font-size: 0.9rem;
		color: #ccc;
		font-weight: 600;
	}
	
	.form-group input,
	.form-group textarea {
		width: 100%;
		padding: 0.75rem;
		background: #2a2a2a;
		border: 1px solid #444;
		border-radius: 6px;
		color: white;
		font-size: 0.9rem;
		box-sizing: border-box;
	}
	
	.form-group textarea {
		resize: vertical;
		min-height: 80px;
	}
	
	.form-group input:focus,
	.form-group textarea:focus {
		outline: none;
		border-color: #3b82f6;
		box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
	}
	
	.modal-footer {
		padding: 0 1.5rem 1.5rem 1.5rem;
		display: flex;
		gap: 1rem;
		justify-content: flex-end;
	}
	
	.cancel-btn {
		padding: 0.75rem 1.5rem;
		background: transparent;
		border: 1px solid #555;
		color: white;
		border-radius: 6px;
		cursor: pointer;
		font-weight: 600;
		transition: background-color 0.2s;
	}
	
	.cancel-btn:hover {
		background: #2a2a2a;
	}
	
	.save-btn {
		padding: 0.75rem 1.5rem;
		background: #10b981;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		font-weight: 600;
		transition: background-color 0.2s;
	}
	
	.save-btn:hover:not(:disabled) {
		background: #059669;
	}
	
	.save-btn:disabled {
		background: #555;
		cursor: not-allowed;
	}
</style>