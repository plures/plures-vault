<script lang="ts">
	import { onMount } from 'svelte';
	import { vaultAPI } from '$lib/api.js';
	import { vaultState } from '$lib/state/vault.svelte.js';
	import { praxisState } from '$lib/state/praxis.svelte.js';

	import MasterPasswordPrompt from '$lib/components/MasterPasswordPrompt.svelte';
	import VaultSidebar from '$lib/components/VaultSidebar.svelte';
	import PartitionTabs from '$lib/components/PartitionTabs.svelte';
	import PasswordGrid from '$lib/components/PasswordGrid.svelte';
	import CredentialForm from '$lib/components/CredentialForm.svelte';
	import AuditLog from '$lib/components/AuditLog.svelte';
	import PartitionManager from '$lib/components/PartitionManager.svelte';
	import type { CredentialData, PartitionData } from '$lib/api.js';

	// -------------------------------------------------------------------------
	// Initialisation
	// -------------------------------------------------------------------------
	onMount(async () => {
		await checkStatus();
	});

	async function checkStatus() {
		try {
			vaultState.isLoading = true;
			vaultState.status = await vaultAPI.checkStatus();
			if (vaultState.status.unlocked) {
				await loadCredentials();
			}
		} catch (e) {
			vaultState.error = e instanceof Error ? e.message : 'Failed to load vault status';
		} finally {
			vaultState.isLoading = false;
		}
	}

	// -------------------------------------------------------------------------
	// Vault unlock / init
	// -------------------------------------------------------------------------
	async function handleUnlock(password: string) {
		const isInit = vaultState.status?.initialized ?? false;
		try {
			if (!isInit) {
				await vaultAPI.initialize('My Vault', password);
				praxisState.log('vault.initialized');
			} else {
				await vaultAPI.unlock(password);
				praxisState.log('vault.unlocked');
			}
			vaultState.status = { ...vaultState.status!, unlocked: true };
			await loadCredentials();
		} catch (e) {
			praxisState.log('vault.unlock_failed', {
				success: false,
				errorMessage: e instanceof Error ? e.message : 'Unknown error',
			});
			throw e;
		}
	}

	async function handleLock() {
		try {
			await vaultAPI.lock();
			praxisState.log('vault.locked');
			vaultState.status = vaultState.status ? { ...vaultState.status, unlocked: false } : null;
			vaultState.credentials = [];
		} catch (e) {
			vaultState.error = e instanceof Error ? e.message : 'Failed to lock vault';
		}
	}

	// -------------------------------------------------------------------------
	// Credentials
	// -------------------------------------------------------------------------
	async function loadCredentials() {
		try {
			vaultState.credentials = await vaultAPI.listCredentials();
			vaultState.updatePartitionCount();
		} catch (e) {
			vaultState.error = e instanceof Error ? e.message : 'Failed to load credentials';
		}
	}

	async function handleAddCredential(data: CredentialData) {
		await vaultAPI.addCredential(data);
		praxisState.log('credential.created', {
			credentialName: data.name,
			partition: vaultState.currentPartition,
		});
		await loadCredentials();
		vaultState.showAddDialog = false;
	}

	async function handleEditCredential(data: CredentialData) {
		const id = vaultState.editingCredentialId!;
		await vaultAPI.updateCredential(id, data);
		praxisState.log('credential.updated', {
			credentialId: id,
			credentialName: data.name,
			partition: vaultState.currentPartition,
		});
		await loadCredentials();
		vaultState.editingCredentialId = null;
	}

	async function handleDeleteCredential(id: string) {
		if (!confirm('Are you sure you want to delete this credential?')) return;
		const cred = vaultState.credentials.find((c) => c.id === id);
		await vaultAPI.deleteCredential(id);
		praxisState.log('credential.deleted', {
			credentialId: id,
			credentialName: cred?.name,
			partition: vaultState.currentPartition,
		});
		await loadCredentials();
	}

	async function handleCopyPassword(id: string, name: string) {
		const cred = await vaultAPI.getCredential(id);
		await navigator.clipboard.writeText(cred.password);
		praxisState.log('credential.password_copied', {
			credentialId: id,
			credentialName: name,
			partition: vaultState.currentPartition,
		});
	}

	async function handleCopyUsername(id: string, name: string) {
		const cred = vaultState.credentials.find((c) => c.id === id);
		if (cred) {
			await navigator.clipboard.writeText(cred.username);
			praxisState.log('credential.username_copied', {
				credentialId: id,
				credentialName: name,
				partition: vaultState.currentPartition,
			});
		}
	}

	// -------------------------------------------------------------------------
	// Partitions
	// -------------------------------------------------------------------------
	function handlePartitionChange(id: string) {
		vaultState.currentPartition = id;
		praxisState.log('partition.switched', { partition: id });
	}

	function handleCreatePartition(partial: Omit<PartitionData, 'id' | 'passwordCount'>) {
		const newPartition: PartitionData = {
			id: crypto.randomUUID(),
			passwordCount: 0,
			...partial,
		};
		vaultState.partitions = [...vaultState.partitions, newPartition];
		praxisState.log('partition.created', { partition: newPartition.name });
	}

	// -------------------------------------------------------------------------
	// Editing
	// -------------------------------------------------------------------------
	const editingCredential = $derived(
		vaultState.editingCredentialId
			? vaultState.credentials.find((c) => c.id === vaultState.editingCredentialId)
			: undefined
	);
</script>

<div class="app-shell">
	{#if vaultState.isLoading && !vaultState.status}
		<!-- Initial load spinner -->
		<div class="loading-fullscreen" aria-busy="true" aria-label="Loading vault">
			<div class="spinner-lg"></div>
			<p>Loading…</p>
		</div>
	{:else if !vaultState.status?.unlocked}
		<!-- Unlock / init screen -->
		<MasterPasswordPrompt
			isInitialized={vaultState.status?.initialized ?? false}
			onunlock={handleUnlock}
		/>
	{:else}
		<!-- Main vault shell -->
		<aside class="sidebar-pane">
			<VaultSidebar
				partitions={vaultState.partitions}
				currentPartition={vaultState.currentPartition}
				vaultName={vaultState.status.vault_name}
				activeView={vaultState.activeView}
				onpartitionchange={handlePartitionChange}
				onlock={handleLock}
				onviewchange={(v) => (vaultState.activeView = v)}
			/>
		</aside>

		<main class="main-pane" aria-label="Vault content">
			{#if vaultState.error}
				<div class="error-banner" role="alert">
					{vaultState.error}
					<button onclick={() => (vaultState.error = '')}>✕</button>
				</div>
			{/if}

			{#if vaultState.activeView === 'passwords'}
				<!-- Partition tabs + password grid -->
				<div class="view-header">
					<PartitionTabs
						partitions={vaultState.partitions}
						currentPartition={vaultState.currentPartition}
						onchange={handlePartitionChange}
						onadd={() => (vaultState.activeView = 'settings')}
					/>

					<div class="toolbar">
						<input
							type="search"
							bind:value={vaultState.searchQuery}
							placeholder="Search credentials…"
							class="search-input"
							aria-label="Search credentials"
						/>
						<button
							class="add-btn"
							onclick={() => (vaultState.showAddDialog = true)}
							aria-label="Add new credential"
						>
							+ Add
						</button>
					</div>
				</div>

				{#if vaultState.isLoading}
					<div class="loading-inline" aria-busy="true">
						<div class="spinner-sm"></div>
					</div>
				{:else}
					<PasswordGrid
						credentials={vaultState.filteredCredentials}
						onadd={() => (vaultState.showAddDialog = true)}
						onedit={(id) => (vaultState.editingCredentialId = id)}
						ondelete={handleDeleteCredential}
						oncopypassword={handleCopyPassword}
						oncopyusername={handleCopyUsername}
					/>
				{/if}
			{:else if vaultState.activeView === 'audit'}
				<div class="view-content">
					<AuditLog entries={praxisState.auditLog} />
				</div>
			{:else if vaultState.activeView === 'settings'}
				<div class="view-content">
					<PartitionManager
						partitions={vaultState.partitions}
						onswitch={handlePartitionChange}
						oncreate={handleCreatePartition}
					/>
				</div>
			{/if}
		</main>
	{/if}

	<!-- Add credential dialog -->
	{#if vaultState.showAddDialog}
		<CredentialForm
			mode="add"
			onsubmit={handleAddCredential}
			oncancel={() => (vaultState.showAddDialog = false)}
		/>
	{/if}

	<!-- Edit credential dialog -->
	{#if vaultState.editingCredentialId && editingCredential}
		<CredentialForm
			mode="edit"
			initial={editingCredential}
			onsubmit={handleEditCredential}
			oncancel={() => (vaultState.editingCredentialId = null)}
		/>
	{/if}
</div>

<style>
	/* ------------------------------------------------------------------ */
	/* App shell layout                                                      */
	/* ------------------------------------------------------------------ */
	.app-shell {
		display: grid;
		grid-template-columns: 240px 1fr;
		height: 100vh;
		overflow: hidden;
		background: var(--color-background);
	}

	.sidebar-pane {
		overflow-y: auto;
	}

	.main-pane {
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	/* ------------------------------------------------------------------ */
	/* Loading states                                                        */
	/* ------------------------------------------------------------------ */
	.loading-fullscreen {
		grid-column: 1 / -1;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: var(--space-4);
		color: var(--color-foreground-muted);
		font-size: var(--font-size-sm);
	}

	.spinner-lg {
		width: 40px;
		height: 40px;
		border: 3px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: var(--radius-full);
		animation: spin 0.8s linear infinite;
	}

	.spinner-sm {
		width: 20px;
		height: 20px;
		border: 2px solid var(--color-border);
		border-top-color: var(--color-primary);
		border-radius: var(--radius-full);
		animation: spin 0.6s linear infinite;
	}

	.loading-inline {
		display: flex;
		justify-content: center;
		padding: var(--space-8);
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}

	/* ------------------------------------------------------------------ */
	/* Error banner                                                           */
	/* ------------------------------------------------------------------ */
	.error-banner {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		padding: var(--space-3) var(--space-6);
		background: var(--color-destructive-subtle);
		border-bottom: 1px solid var(--color-destructive);
		color: var(--color-destructive);
		font-size: var(--font-size-sm);
		flex-shrink: 0;
	}

	.error-banner button {
		background: transparent;
		border: none;
		color: inherit;
		cursor: pointer;
		font-size: var(--font-size-base);
		padding: 0;
		line-height: 1;
	}

	/* ------------------------------------------------------------------ */
	/* Passwords view                                                         */
	/* ------------------------------------------------------------------ */
	.view-header {
		padding: var(--space-6) var(--space-6) 0;
		flex-shrink: 0;
	}

	.toolbar {
		display: flex;
		gap: var(--space-3);
		margin-bottom: var(--space-2);
	}

	.search-input {
		flex: 1;
		padding: var(--space-2) var(--space-4);
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-sans);
		outline: none;
		transition: border-color var(--transition-fast);
	}

	.search-input:focus {
		border-color: var(--color-primary);
	}

	.add-btn {
		padding: var(--space-2) var(--space-5);
		background: var(--color-success);
		color: var(--color-success-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		white-space: nowrap;
		transition: background-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.add-btn:hover {
		background: color-mix(in srgb, var(--color-success) 85%, black);
	}

	/* ------------------------------------------------------------------ */
	/* Generic scrollable view area                                          */
	/* ------------------------------------------------------------------ */
	.view-content {
		flex: 1;
		overflow-y: auto;
		padding: var(--space-6);
	}

	:global(.main-pane > .password-grid-wrapper) {
		flex: 1;
		overflow-y: auto;
		padding: 0 var(--space-6) var(--space-6);
	}
</style>