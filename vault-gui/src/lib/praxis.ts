/**
 * Praxis Ledger Integration
 *
 * All user actions in Plures Vault are logged through Praxis for:
 *   - Security behavior analysis and pattern detection
 *   - Compliance reporting (enterprise audit logs)
 *   - Decision trail (why passwords were created/modified/shared)
 *   - Cross-partition activity correlation
 */

export type PraxisActionType =
	| 'vault.initialized'
	| 'vault.unlocked'
	| 'vault.locked'
	| 'vault.unlock_failed'
	| 'credential.created'
	| 'credential.read'
	| 'credential.updated'
	| 'credential.deleted'
	| 'credential.password_copied'
	| 'credential.username_copied'
	| 'partition.created'
	| 'partition.switched'
	| 'partition.synced'
	| 'sync.started'
	| 'sync.completed'
	| 'sync.failed'
	| 'security.password_generated'
	| 'security.breach_check'
	| 'settings.changed';

export type PraxisActionSeverity = 'info' | 'warning' | 'critical';

export interface PraxisAction {
	id: string;
	action: PraxisActionType;
	severity: PraxisActionSeverity;
	/** ISO 8601 timestamp */
	timestamp: string;
	partition?: string;
	credentialId?: string;
	credentialName?: string;
	/** Arbitrary structured metadata for this action */
	details?: Record<string, unknown>;
	success: boolean;
	errorMessage?: string;
}

export interface PraxisPattern {
	id: string;
	name: string;
	description: string;
	detectedAt: string;
	actions: PraxisAction[];
	riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function createPraxisAction(
	action: PraxisActionType,
	options: {
		partition?: string;
		credentialId?: string;
		credentialName?: string;
		details?: Record<string, unknown>;
		success?: boolean;
		errorMessage?: string;
	} = {}
): Omit<PraxisAction, 'id'> {
	return {
		action,
		severity: getActionSeverity(action, options.success ?? true),
		timestamp: new Date().toISOString(),
		success: options.success ?? true,
		...options,
	};
}

function getActionSeverity(action: PraxisActionType, success: boolean): PraxisActionSeverity {
	if (!success && (action === 'vault.unlock_failed' || action === 'sync.failed')) {
		return 'critical';
	}
	if (!success) return 'warning';
	if (action === 'credential.deleted' || action === 'vault.locked') return 'warning';
	return 'info';
}

/** Human-readable label for an action type */
export function formatActionLabel(action: PraxisActionType): string {
	const labels: Record<PraxisActionType, string> = {
		'vault.initialized': 'Vault Initialized',
		'vault.unlocked': 'Vault Unlocked',
		'vault.locked': 'Vault Locked',
		'vault.unlock_failed': 'Unlock Failed',
		'credential.created': 'Credential Created',
		'credential.read': 'Credential Viewed',
		'credential.updated': 'Credential Updated',
		'credential.deleted': 'Credential Deleted',
		'credential.password_copied': 'Password Copied',
		'credential.username_copied': 'Username Copied',
		'partition.created': 'Partition Created',
		'partition.switched': 'Partition Switched',
		'partition.synced': 'Partition Synced',
		'sync.started': 'Sync Started',
		'sync.completed': 'Sync Completed',
		'sync.failed': 'Sync Failed',
		'security.password_generated': 'Password Generated',
		'security.breach_check': 'Breach Check Run',
		'settings.changed': 'Settings Changed',
	};
	return labels[action] ?? action;
}

/** Relative time string, e.g. "2 minutes ago" */
export function formatRelativeTime(isoTimestamp: string): string {
	const diff = Date.now() - new Date(isoTimestamp).getTime();
	const seconds = Math.floor(diff / 1000);
	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}
