<!--
  PasswordGenerator – in-app password generator
  Allows customizing length, character classes, and copies/returns the result.
-->
<script lang="ts">
	interface Props {
		ongenerate?: (password: string) => void;
	}

	let { ongenerate }: Props = $props();

	let length = $state(20);
	let useUppercase = $state(true);
	let useLowercase = $state(true);
	let useNumbers = $state(true);
	let useSymbols = $state(false);
	let generated = $state('');
	let copied = $state(false);

	const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	const LOWER = 'abcdefghijklmnopqrstuvwxyz';
	const NUMS = '0123456789';
	const SYMS = '!@#$%^&*()-_=+[]{}|;:,.<>?';

	function generate() {
		let charset = '';
		if (useUppercase) charset += UPPER;
		if (useLowercase) charset += LOWER;
		if (useNumbers) charset += NUMS;
		if (useSymbols) charset += SYMS;

		if (!charset) {
			charset = LOWER + NUMS;
		}

		const arr = new Uint32Array(length);
		crypto.getRandomValues(arr);
		generated = Array.from(arr)
			.map((n) => charset[n % charset.length])
			.join('');
	}

	async function copyToClipboard() {
		if (!generated) return;
		try {
			await navigator.clipboard.writeText(generated);
			copied = true;
			setTimeout(() => (copied = false), 1500);
		} catch {
			// Clipboard API may be unavailable in some contexts
		}
	}

	function usePassword() {
		if (generated) ongenerate?.(generated);
	}

	// Auto-generate on mount and whenever any option changes.
	// $effect tracks all reactive reads inside its body — reading each variable
	// is sufficient to register the dependency.
	$effect(() => {
		const _deps = [length, useUppercase, useLowercase, useNumbers, useSymbols];
		void _deps; // consumed to satisfy linters
		generate();
	});
</script>

<div class="generator">
	<div class="controls">
		<div class="length-row">
			<label for="gen-length" class="control-label">Length: <strong>{length}</strong></label>
			<input
				id="gen-length"
				type="range"
				bind:value={length}
				min="8"
				max="64"
				step="1"
				class="range-input"
				aria-label="Password length: {length}"
			/>
		</div>

		<div class="checkboxes">
			<label class="checkbox-label">
				<input type="checkbox" bind:checked={useUppercase} />
				A–Z Uppercase
			</label>
			<label class="checkbox-label">
				<input type="checkbox" bind:checked={useLowercase} />
				a–z Lowercase
			</label>
			<label class="checkbox-label">
				<input type="checkbox" bind:checked={useNumbers} />
				0–9 Numbers
			</label>
			<label class="checkbox-label">
				<input type="checkbox" bind:checked={useSymbols} />
				!@# Symbols
			</label>
		</div>
	</div>

	{#if generated}
		<div class="output">
			<code class="generated-password" aria-label="Generated password">{generated}</code>
			<div class="output-actions">
				<button class="action-btn" onclick={generate} title="Regenerate" aria-label="Regenerate password">
					🔄
				</button>
				<button
					class="action-btn"
					onclick={copyToClipboard}
					title={copied ? 'Copied!' : 'Copy'}
					aria-label={copied ? 'Copied to clipboard' : 'Copy to clipboard'}
				>
					{copied ? '✅' : '📋'}
				</button>
				{#if ongenerate}
					<button class="use-btn" onclick={usePassword}>Use This Password</button>
				{/if}
			</div>
		</div>
	{/if}
</div>

<style>
	.generator {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}

	.controls {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.length-row {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}

	.control-label {
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
	}

	.range-input {
		width: 100%;
		accent-color: var(--color-primary);
	}

	.checkboxes {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: var(--space-2);
	}

	.checkbox-label {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--font-size-sm);
		color: var(--color-foreground);
		cursor: pointer;
	}

	.checkbox-label input[type='checkbox'] {
		accent-color: var(--color-primary);
		width: 14px;
		height: 14px;
		cursor: pointer;
	}

	.output {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}

	.generated-password {
		display: block;
		padding: var(--space-3) var(--space-4);
		background: var(--color-background);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		font-family: var(--font-family-mono);
		font-size: var(--font-size-sm);
		color: var(--color-foreground);
		word-break: break-all;
		letter-spacing: 0.04em;
	}

	.output-actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}

	.action-btn {
		background: transparent;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		padding: var(--space-2) var(--space-3);
		cursor: pointer;
		font-size: var(--font-size-sm);
		color: var(--color-foreground-muted);
		transition: color var(--transition-fast), background-color var(--transition-fast);
	}

	.action-btn:hover {
		color: var(--color-foreground);
		background: var(--color-surface-hover);
	}

	.use-btn {
		margin-left: auto;
		padding: var(--space-2) var(--space-4);
		background: var(--color-primary);
		color: var(--color-primary-foreground);
		border: none;
		border-radius: var(--radius-md);
		font-size: var(--font-size-sm);
		font-weight: var(--font-weight-semibold);
		cursor: pointer;
		font-family: var(--font-family-sans);
		transition: background-color var(--transition-fast);
	}

	.use-btn:hover {
		background: var(--color-primary-hover);
	}
</style>
