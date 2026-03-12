<script lang="ts">
	interface Props {
		isInitialized?: boolean;
		onunlock: (password: string) => Promise<void>;
	}

	let { isInitialized = false, onunlock }: Props = $props();

	let password = $state('');
	let showPassword = $state(false);
	let isLoading = $state(false);
	let error = $state('');

	const isValid = $derived(password.trim().length >= 1);

	async function handleSubmit() {
		if (!isValid || isLoading) return;
		isLoading = true;
		error = '';
		try {
			await onunlock(password);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Authentication failed';
		} finally {
			isLoading = false;
		}
	}

	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') handleSubmit();
	}
</script>

<div
	class="unlock-overlay"
	role="dialog"
	aria-label="Unlock vault"
	aria-modal="true"
>
	<div class="unlock-container">
		<div class="unlock-header">
			<div class="vault-icon" aria-hidden="true">🔐</div>
			<h1>Plures Vault</h1>
			<p>
				{#if isInitialized}
					Enter your master password to unlock your vault
				{:else}
					Create a master password to initialize your vault
				{/if}
			</p>
		</div>

		<div class="unlock-form">
			<div class="field-wrapper">
				<label for="master-password" class="sr-only">Master Password</label>
				<div class="input-group">
					<input
						id="master-password"
						type={showPassword ? 'text' : 'password'}
						bind:value={password}
						placeholder="Master password"
						disabled={isLoading}
						onkeydown={handleKeydown}
						autocomplete={isInitialized ? 'current-password' : 'new-password'}
						aria-describedby={error ? 'password-error' : undefined}
						class="password-input"
						autofocus
					/>
					<button
						type="button"
						class="visibility-toggle"
						onclick={() => (showPassword = !showPassword)}
						aria-label={showPassword ? 'Hide password' : 'Show password'}
						tabindex="0"
					>
						{showPassword ? '🙈' : '👁️'}
					</button>
				</div>

				{#if error}
					<div id="password-error" class="error-text" role="alert">{error}</div>
				{/if}
			</div>

			<button
				type="button"
				class="submit-btn"
				onclick={handleSubmit}
				disabled={!isValid || isLoading}
				aria-busy={isLoading}
			>
				{#if isLoading}
					<span class="spinner" aria-hidden="true"></span>
					{isInitialized ? 'Unlocking…' : 'Creating…'}
				{:else}
					{isInitialized ? 'Unlock Vault' : 'Create Vault'}
				{/if}
			</button>
		</div>

		<div class="unlock-footer">
			<p class="security-note">
				<strong>Zero-knowledge security:</strong> Your master password never leaves this device.
			</p>
		</div>
	</div>
</div>

<style>
	.unlock-overlay {
		position: fixed;
		inset: 0;
		background: var(--color-background);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: var(--z-modal);
	}

	.unlock-container {
		max-width: 420px;
		width: 90%;
		padding: var(--space-8);
		background: var(--color-surface);
		border-radius: var(--radius-xl);
		border: 1px solid var(--color-border);
		box-shadow: var(--shadow-xl);
	}

	.unlock-header {
		text-align: center;
		margin-bottom: var(--space-6);
	}

	.vault-icon {
		font-size: 2.5rem;
		margin-bottom: var(--space-3);
	}

	.unlock-header h1 {
		font-size: var(--font-size-2xl);
		font-weight: var(--font-weight-bold);
		margin: 0 0 var(--space-2) 0;
		color: var(--color-foreground);
	}

	.unlock-header p {
		color: var(--color-foreground-muted);
		margin: 0;
		font-size: var(--font-size-sm);
	}

	.unlock-form {
		margin-bottom: var(--space-6);
	}

	.field-wrapper {
		margin-bottom: var(--space-4);
	}

	.input-group {
		display: flex;
		align-items: center;
		background: var(--color-surface-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		overflow: hidden;
		transition: border-color var(--transition-fast);
	}

	.input-group:focus-within {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-subtle);
	}

	.password-input {
		flex: 1;
		padding: var(--space-3) var(--space-4);
		background: transparent;
		border: none;
		color: var(--color-foreground);
		font-size: var(--font-size-base);
		outline: none;
		font-family: var(--font-family-mono);
	}

	.password-input::placeholder {
		color: var(--color-foreground-subtle);
		font-family: var(--font-family-sans);
	}

	.visibility-toggle {
		padding: var(--space-2) var(--space-3);
		background: transparent;
		border: none;
		cursor: pointer;
		font-size: var(--font-size-base);
		color: var(--color-foreground-muted);
		transition: color var(--transition-fast);
	}

	.visibility-toggle:hover {
		color: var(--color-foreground);
	}

	.error-text {
		color: var(--color-destructive);
		font-size: var(--font-size-sm);
		margin-top: var(--space-2);
		text-align: center;
	}

	.submit-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		width: 100%;
		padding: var(--space-3) var(--space-4);
		background: var(--color-primary);
		color: var(--color-primary-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-base);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		transition: background-color var(--transition-fast);
	}

	.submit-btn:hover:not(:disabled) {
		background: var(--color-primary-hover);
	}

	.submit-btn:disabled {
		background: var(--color-border-hover);
		cursor: not-allowed;
		opacity: 0.6;
	}

	.spinner {
		display: inline-block;
		width: 16px;
		height: 16px;
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

	.unlock-footer {
		text-align: center;
	}

	.security-note {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		margin: 0;
	}
</style>