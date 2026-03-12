<!--
  CredentialForm – add / edit credential dialog (Svelte 5 runes)
  Includes: PasswordField with strength meter, URL validation, notes.
-->
<script lang="ts">
	import type { CredentialData } from '$lib/api.js';
	import PasswordField from './PasswordField.svelte';
	import PasswordGenerator from './PasswordGenerator.svelte';

	interface Props {
		initial?: Partial<CredentialData>;
		mode?: 'add' | 'edit';
		onsubmit: (data: CredentialData) => Promise<void>;
		oncancel: () => void;
	}

	let { initial = {}, mode = 'add', onsubmit, oncancel }: Props = $props();

	// Capturing initial prop values in $state is intentional here —
	// this dialog is always mounted fresh per credential (key'd by id in parent).
	// eslint-disable-next-line svelte/state_referenced_locally
	let name = $state(initial.name ?? '');
	// eslint-disable-next-line svelte/state_referenced_locally
	let username = $state(initial.username ?? '');
	// eslint-disable-next-line svelte/state_referenced_locally
	let password = $state(initial.password ?? '');
	// eslint-disable-next-line svelte/state_referenced_locally
	let url = $state(initial.url ?? '');
	// eslint-disable-next-line svelte/state_referenced_locally
	let notes = $state(initial.notes ?? '');

	let isLoading = $state(false);
	let error = $state('');
	let showGenerator = $state(false);

	const isValid = $derived(name.trim().length > 0 && username.trim().length > 0);

	async function handleSubmit() {
		if (!isValid || isLoading) return;
		isLoading = true;
		error = '';
		try {
			await onsubmit({ name: name.trim(), username: username.trim(), password, url, notes });
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save credential';
		} finally {
			isLoading = false;
		}
	}

	function handleGeneratedPassword(generated: string) {
		password = generated;
		showGenerator = false;
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Escape') oncancel();
	}
</script>

<!-- Modal backdrop implemented as a fixed overlay with button for keyboard accessibility -->
<div class="modal-backdrop" role="presentation">
	<!-- Invisible full-screen close button behind the modal -->
	<button
		type="button"
		class="backdrop-close"
		onclick={oncancel}
		aria-label="Close dialog"
		tabindex="-1"
	></button>

	<div
		class="modal"
		onclick={(e) => e.stopPropagation()}
		onkeydown={handleKeydown}
		role="dialog"
		aria-label="{mode === 'add' ? 'Add' : 'Edit'} credential"
		aria-modal="true"
		tabindex="-1"
	>
		<div class="modal-header">
			<h2>{mode === 'add' ? 'Add Credential' : 'Edit Credential'}</h2>
			<button class="close-btn" onclick={oncancel} aria-label="Close dialog">✕</button>
		</div>

		<div class="modal-body">
			{#if error}
				<div class="error-banner" role="alert">{error}</div>
			{/if}

			<div class="form-group">
				<label for="cred-name" class="form-label">Name <span class="required">*</span></label>
				<input
					id="cred-name"
					bind:value={name}
					placeholder="e.g. GitHub, Gmail, Stripe"
					class="form-input"
					autocomplete="off"
				/>
			</div>

			<div class="form-group">
				<label for="cred-username" class="form-label"
					>Username / Email <span class="required">*</span></label
				>
				<input
					id="cred-username"
					bind:value={username}
					placeholder="username or email"
					class="form-input"
					autocomplete="username"
				/>
			</div>

			<div class="form-group">
				<div class="label-row">
					<label for="cred-password" class="form-label">Password</label>
					<button
						type="button"
						class="generate-link"
						onclick={() => (showGenerator = !showGenerator)}
						aria-expanded={showGenerator}
					>
						{showGenerator ? 'Hide generator' : '⚡ Generate'}
					</button>
				</div>

				{#if showGenerator}
					<div class="generator-panel">
						<PasswordGenerator ongenerate={handleGeneratedPassword} />
					</div>
				{/if}

				<PasswordField
					id="cred-password"
					bind:value={password}
					label=""
					placeholder="Leave empty to not set/change"
					showStrength={true}
					autocomplete={mode === 'add' ? 'new-password' : 'current-password'}
				/>
			</div>

			<div class="form-group">
				<label for="cred-url" class="form-label">URL</label>
				<input
					id="cred-url"
					bind:value={url}
					placeholder="https://example.com"
					class="form-input"
					autocomplete="url"
					type="url"
				/>
			</div>

			<div class="form-group">
				<label for="cred-notes" class="form-label">Notes</label>
				<textarea
					id="cred-notes"
					bind:value={notes}
					placeholder="Optional notes (2FA secrets, recovery codes, etc.)"
					class="form-textarea"
					rows="3"
				></textarea>
			</div>
		</div>

		<div class="modal-footer">
			<button type="button" class="cancel-btn" onclick={oncancel}>Cancel</button>
			<button
				type="button"
				class="submit-btn"
				onclick={handleSubmit}
				disabled={!isValid || isLoading}
				aria-busy={isLoading}
			>
				{#if isLoading}
					<span class="spinner" aria-hidden="true"></span>
					Saving…
				{:else}
					{mode === 'add' ? 'Add Credential' : 'Save Changes'}
				{/if}
			</button>
		</div>
	</div>
</div>

<style>
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.75);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: var(--z-modal);
		padding: var(--space-4);
	}

	.backdrop-close {
		position: absolute;
		inset: 0;
		background: transparent;
		border: none;
		cursor: pointer;
		width: 100%;
		height: 100%;
	}

	.modal {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-xl);
		width: 100%;
		max-width: 520px;
		max-height: 90vh;
		display: flex;
		flex-direction: column;
		box-shadow: var(--shadow-xl);
		position: relative;
		z-index: 1;
	}

	.modal-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		padding: var(--space-6) var(--space-6) 0;
	}

	.modal-header h2 {
		margin: 0;
		font-size: var(--font-size-xl);
		font-weight: var(--font-weight-bold);
	}

	.close-btn {
		background: transparent;
		border: none;
		color: var(--color-foreground-muted);
		font-size: var(--font-size-lg);
		cursor: pointer;
		padding: var(--space-1);
		border-radius: var(--radius-sm);
		transition: color var(--transition-fast);
		line-height: 1;
	}

	.close-btn:hover {
		color: var(--color-foreground);
	}

	.modal-body {
		padding: var(--space-6);
		overflow-y: auto;
		flex: 1;
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.error-banner {
		padding: var(--space-3);
		background: var(--color-destructive-subtle);
		border: 1px solid var(--color-destructive);
		border-radius: var(--radius-md);
		color: var(--color-destructive);
		font-size: var(--font-size-sm);
	}

	.form-group {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}

	.form-label {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		color: var(--color-foreground-muted);
	}

	.required {
		color: var(--color-destructive);
	}

	.label-row {
		display: flex;
		justify-content: space-between;
		align-items: center;
	}

	.generate-link {
		background: transparent;
		border: none;
		color: var(--color-primary);
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-medium);
		cursor: pointer;
		padding: 0;
		font-family: var(--font-family-sans);
		transition: opacity var(--transition-fast);
	}

	.generate-link:hover {
		opacity: 0.75;
	}

	.generator-panel {
		background: var(--color-surface-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		padding: var(--space-4);
		margin-bottom: var(--space-2);
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
		transition:
			border-color var(--transition-fast),
			box-shadow var(--transition-fast);
	}

	.form-input:focus {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-subtle);
	}

	.form-textarea {
		padding: var(--space-3) var(--space-4);
		background: var(--color-surface-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-sans);
		outline: none;
		resize: vertical;
		min-height: 80px;
		transition:
			border-color var(--transition-fast),
			box-shadow var(--transition-fast);
	}

	.form-textarea:focus {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-subtle);
	}

	.modal-footer {
		display: flex;
		justify-content: flex-end;
		gap: var(--space-3);
		padding: 0 var(--space-6) var(--space-6);
	}

	.cancel-btn {
		padding: var(--space-3) var(--space-5);
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		cursor: pointer;
		transition: background-color var(--transition-fast);
		font-family: var(--font-family-sans);
	}

	.cancel-btn:hover {
		background: var(--color-surface-hover);
	}

	.submit-btn {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-3) var(--space-5);
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

	.spinner {
		display: inline-block;
		width: 14px;
		height: 14px;
		border: 2px solid rgba(255, 255, 255, 0.3);
		border-top-color: white;
		border-radius: var(--radius-full);
		animation: spin 0.6s linear infinite;
	}

	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
</style>
