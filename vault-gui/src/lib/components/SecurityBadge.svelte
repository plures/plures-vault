<!-- SecurityBadge – visual security status indicator -->
<script lang="ts">
	type Status = 'secure' | 'warning' | 'critical' | 'info' | 'synced' | 'syncing' | 'offline';

	interface Props {
		status: Status;
		label?: string;
	}

	let { status, label }: Props = $props();

	const config: Record<Status, { icon: string; color: string; defaultLabel: string }> = {
		secure: { icon: '✅', color: 'var(--color-success)', defaultLabel: 'Secure' },
		warning: { icon: '⚠️', color: 'var(--color-warning)', defaultLabel: 'Warning' },
		critical: { icon: '🚨', color: 'var(--color-destructive)', defaultLabel: 'Critical' },
		info: { icon: 'ℹ️', color: 'var(--color-info)', defaultLabel: 'Info' },
		synced: { icon: '🔄', color: 'var(--color-success)', defaultLabel: 'Synced' },
		syncing: { icon: '⏳', color: 'var(--color-warning)', defaultLabel: 'Syncing…' },
		offline: { icon: '📵', color: 'var(--color-foreground-muted)', defaultLabel: 'Offline' },
	};

	const cfg = $derived(config[status]);
	const displayLabel = $derived(label ?? cfg.defaultLabel);
</script>

<span
	class="badge"
	style="--badge-color: {cfg.color}"
	role="status"
	aria-label="{displayLabel}"
>
	<span class="badge-icon" aria-hidden="true">{cfg.icon}</span>
	<span class="badge-label">{displayLabel}</span>
</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: var(--space-1) var(--space-2);
		background: color-mix(in srgb, var(--badge-color) 15%, transparent);
		border: 1px solid color-mix(in srgb, var(--badge-color) 35%, transparent);
		border-radius: var(--radius-full);
		font-size: var(--font-size-xs);
		font-weight: var(--font-weight-medium);
		color: var(--badge-color);
		white-space: nowrap;
		user-select: none;
	}

	.badge-icon {
		font-size: 0.7rem;
	}
</style>
