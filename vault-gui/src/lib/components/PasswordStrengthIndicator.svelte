<script lang="ts">
	interface Props {
		password?: string;
	}

	let { password = '' }: Props = $props();

	type StrengthLevel = 'none' | 'weak' | 'fair' | 'good' | 'strong' | 'very-strong';

	interface StrengthResult {
		level: StrengthLevel;
		score: number; // 0–5
		label: string;
		color: string;
		suggestions: string[];
	}

	function evaluateStrength(pw: string): StrengthResult {
		if (!pw) {
			return { level: 'none', score: 0, label: '', color: 'transparent', suggestions: [] };
		}

		let score = 0;
		const suggestions: string[] = [];

		if (pw.length >= 8) score++;
		else suggestions.push('Use at least 8 characters');

		if (pw.length >= 16) score++;
		else if (pw.length >= 8) suggestions.push('12+ characters is better');

		if (/[A-Z]/.test(pw)) score++;
		else suggestions.push('Add uppercase letters');

		if (/[0-9]/.test(pw)) score++;
		else suggestions.push('Add numbers');

		if (/[^A-Za-z0-9]/.test(pw)) score++;
		else suggestions.push('Add symbols (!@#$…)');

		const levels: Record<number, { level: StrengthLevel; label: string; color: string }> = {
			0: { level: 'weak', label: 'Very Weak', color: 'var(--color-strength-weak)' },
			1: { level: 'weak', label: 'Weak', color: 'var(--color-strength-weak)' },
			2: { level: 'fair', label: 'Fair', color: 'var(--color-strength-fair)' },
			3: { level: 'good', label: 'Good', color: 'var(--color-strength-good)' },
			4: { level: 'strong', label: 'Strong', color: 'var(--color-strength-strong)' },
			5: { level: 'very-strong', label: 'Very Strong', color: 'var(--color-strength-very-strong)' },
		};

		const { level, label, color } = levels[score];
		return { level, score, label, color, suggestions };
	}

	const result = $derived(evaluateStrength(password));
	const filledBars = $derived(result.score);
</script>

{#if password}
	<div class="strength-meter" role="group" aria-label="Password strength: {result.label}">
		<div class="bars" aria-hidden="true">
			{#each { length: 5 } as _, i}
				<div
					class="bar"
					class:filled={i < filledBars}
					style="--bar-color: {i < filledBars ? result.color : 'var(--color-border)'}"
				></div>
			{/each}
		</div>

		{#if result.label}
			<span class="label" style="color: {result.color}">{result.label}</span>
		{/if}
	</div>

	{#if result.suggestions.length > 0}
		<ul class="suggestions" aria-label="Password improvement tips">
			{#each result.suggestions.slice(0, 2) as tip}
				<li>{tip}</li>
			{/each}
		</ul>
	{/if}
{/if}

<style>
	.strength-meter {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		margin-top: var(--space-2);
	}

	.bars {
		display: flex;
		gap: var(--space-1);
		flex: 1;
	}

	.bar {
		flex: 1;
		height: 4px;
		border-radius: var(--radius-full);
		background: var(--bar-color);
		transition: background-color var(--transition-base);
	}

	.label {
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-semibold);
		white-space: nowrap;
		min-width: 70px;
		text-align: right;
		transition: color var(--transition-base);
	}

	.suggestions {
		margin: var(--space-2) 0 0 0;
		padding: 0 0 0 var(--space-4);
		list-style: disc;
	}

	.suggestions li {
		font-size: var(--font-size-xs);
		color: var(--color-foreground-muted);
		margin-bottom: var(--space-1);
	}
</style>
