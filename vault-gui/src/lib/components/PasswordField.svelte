<!--
  PasswordField – Accessible password input with:
    • visibility toggle
    • optional inline strength meter
    • keyboard-navigable
-->
<script lang="ts">
	import PasswordStrengthIndicator from './PasswordStrengthIndicator.svelte';

	interface Props {
		value?: string;
		id?: string;
		label?: string;
		placeholder?: string;
		disabled?: boolean;
		showStrength?: boolean;
		autocomplete?: string;
		autofocus?: boolean;
		onchange?: (value: string) => void;
	}

	let {
		value = $bindable(''),
		id = 'password-field',
		label = 'Password',
		placeholder = 'Password',
		disabled = false,
		showStrength = false,
		autocomplete = 'current-password',
		autofocus = false,
		onchange,
	}: Props = $props();

	let showPlain = $state(false);

	function handleInput(event: Event) {
		value = (event.currentTarget as HTMLInputElement).value;
		onchange?.(value);
	}
</script>

<div class="password-field">
	<label for={id} class="field-label">{label}</label>

	<div class="input-wrapper" class:disabled>
		<input
			{id}
			type={showPlain ? 'text' : 'password'}
			{value}
			{placeholder}
			{disabled}
			autocomplete={autocomplete as 'current-password' | 'new-password' | 'off'}
			autofocus={autofocus || undefined}
			oninput={handleInput}
			class="input"
			aria-describedby={showStrength ? `${id}-strength` : undefined}
		/>
		<button
			type="button"
			class="toggle-btn"
			onclick={() => (showPlain = !showPlain)}
			aria-label={showPlain ? 'Hide password' : 'Show password'}
			tabindex="0"
			{disabled}
		>
			{showPlain ? '🙈' : '👁️'}
		</button>
	</div>

	{#if showStrength}
		<div id="{id}-strength">
			<PasswordStrengthIndicator password={value} />
		</div>
	{/if}
</div>

<style>
	.password-field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.field-label {
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-medium);
		color: var(--color-foreground-muted);
	}

	.input-wrapper {
		display: flex;
		align-items: center;
		background: var(--color-surface-elevated);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		overflow: hidden;
		transition:
			border-color var(--transition-fast),
			box-shadow var(--transition-fast);
	}

	.input-wrapper:focus-within {
		border-color: var(--color-primary);
		box-shadow: 0 0 0 3px var(--color-primary-subtle);
	}

	.input-wrapper.disabled {
		opacity: 0.5;
	}

	.input {
		flex: 1;
		padding: var(--space-3) var(--space-4);
		background: transparent;
		border: none;
		color: var(--color-foreground);
		font-size: var(--font-size-sm);
		font-family: var(--font-family-mono);
		outline: none;
	}

	.input::placeholder {
		color: var(--color-foreground-subtle);
		font-family: var(--font-family-sans);
	}

	.toggle-btn {
		flex-shrink: 0;
		padding: var(--space-2) var(--space-3);
		background: transparent;
		border: none;
		cursor: pointer;
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
		transition: color var(--transition-fast);
	}

	.toggle-btn:hover:not(:disabled) {
		color: var(--color-foreground);
	}

	.toggle-btn:disabled {
		cursor: not-allowed;
	}
</style>
