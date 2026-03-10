<script lang="ts">
	import { createEventDispatcher } from 'svelte';
	import { Button, Dialog, Input } from '@plures/design-dojo';
	
	const dispatch = createEventDispatcher();
	
	let masterPassword = '';
	let showDialog = true;
	let isValidating = false;
	let errorMessage = '';
	
	async function handleUnlock() {
		if (!masterPassword.trim()) {
			errorMessage = 'Master password is required';
			return;
		}
		
		isValidating = true;
		errorMessage = '';
		
		try {
			// TODO: Integrate with vault-crypto for actual validation
			await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate validation
			
			dispatch('unlock', { password: masterPassword });
			showDialog = false;
		} catch (error) {
			errorMessage = 'Invalid master password';
		} finally {
			isValidating = false;
		}
	}
	
	function handleKeydown(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			handleUnlock();
		}
	}
</script>

<div class="unlock-overlay">
	<div class="unlock-container">
		<div class="unlock-header">
			<h1>🔐 Plures Vault</h1>
			<p>Enter your master password to unlock your vault</p>
		</div>
		
		<div class="unlock-form">
			<Input
				bind:value={masterPassword}
				type="password"
				placeholder="Master password"
				on:keydown={handleKeydown}
				disabled={isValidating}
				style="width: 100%;"
				autoFocus
			/>
			
			{#if errorMessage}
				<div class="error-message">{errorMessage}</div>
			{/if}
			
			<Button
				on:click={handleUnlock}
				disabled={isValidating || !masterPassword.trim()}
				style="width: 100%; margin-top: var(--space-4);"
			>
				{#if isValidating}
					Unlocking...
				{:else}
					Unlock Vault
				{/if}
			</Button>
		</div>
		
		<div class="unlock-footer">
			<p>
				<strong>Zero-knowledge security:</strong> Your master password never leaves this device.
			</p>
			<p>
				<a href="#forgot">Forgot password?</a> • <a href="#help">Need help?</a>
			</p>
		</div>
	</div>
</div>

<style>
	.unlock-overlay {
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		bottom: 0;
		background: var(--color-background);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	
	.unlock-container {
		max-width: 400px;
		width: 90%;
		padding: var(--space-8);
		background: var(--color-surface);
		border-radius: var(--border-radius-lg);
		border: 1px solid var(--color-border);
		box-shadow: var(--shadow-lg);
	}
	
	.unlock-header {
		text-align: center;
		margin-bottom: var(--space-6);
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
	}
	
	.unlock-form {
		margin-bottom: var(--space-6);
	}
	
	.error-message {
		color: var(--color-destructive);
		font-size: var(--font-size-sm);
		margin-top: var(--space-2);
		text-align: center;
	}
	
	.unlock-footer {
		text-align: center;
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
	}
	
	.unlock-footer p {
		margin: var(--space-2) 0;
	}
	
	.unlock-footer a {
		color: var(--color-primary);
		text-decoration: none;
	}
	
	.unlock-footer a:hover {
		text-decoration: underline;
	}
</style>