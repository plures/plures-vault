/**
 * Praxis audit state – Svelte 5 runes
 *
 * In-memory audit log that captures every vault action for the current session.
 * Actions are also persisted to the backend via Tauri commands for long-term
 * storage and compliance reporting.
 */
import type { PraxisAction, PraxisActionType } from '../praxis.js';
import { createPraxisAction } from '../praxis.js';

const MAX_ENTRIES = 1000;

function createPraxisState() {
	let auditLog = $state<PraxisAction[]>([]);
	let isEnabled = $state(true);

	function log(
		action: PraxisActionType,
		options: Parameters<typeof createPraxisAction>[1] = {}
	): PraxisAction {
		const entry: PraxisAction = {
			id: crypto.randomUUID(),
			...createPraxisAction(action, options),
		};

		if (isEnabled) {
			// Prepend so newest is first; cap at MAX_ENTRIES
			auditLog = [entry, ...auditLog].slice(0, MAX_ENTRIES);
		}

		return entry;
	}

	function clear() {
		auditLog = [];
	}

	function getRecentActions(n = 20): PraxisAction[] {
		return auditLog.slice(0, n);
	}

	function getBySeverity(severity: PraxisAction['severity']): PraxisAction[] {
		return auditLog.filter((e) => e.severity === severity);
	}

	function getByCredential(credentialId: string): PraxisAction[] {
		return auditLog.filter((e) => e.credentialId === credentialId);
	}

	return {
		get auditLog() {
			return auditLog;
		},
		get isEnabled() {
			return isEnabled;
		},
		set isEnabled(v) {
			isEnabled = v;
		},
		log,
		clear,
		getRecentActions,
		getBySeverity,
		getByCredential,
	};
}

export const praxisState = createPraxisState();
