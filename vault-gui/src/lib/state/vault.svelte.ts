/**
 * Vault global state – Svelte 5 runes
 *
 * This is the single canonical source of truth for all vault UI state.
 * Import `vaultState` and access/mutate via its getters/setters.
 */
import type { CredentialData, VaultStatus, PartitionData } from '../api.js';

function createVaultState() {
	let status = $state<VaultStatus | null>(null);
	let credentials = $state<CredentialData[]>([]);
	let currentPartition = $state('personal');
	let partitions = $state<PartitionData[]>([
		{ id: 'personal', name: 'Personal', type: 'local', passwordCount: 0 },
	]);
	let isLoading = $state(false);
	let error = $state('');
	let searchQuery = $state('');
	let activeView = $state<'passwords' | 'audit' | 'settings'>('passwords');
	let showAddDialog = $state(false);
	let editingCredentialId = $state<string | null>(null);

	const filteredCredentials = $derived(
		credentials.filter((c) => {
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase();
			return (
				c.name.toLowerCase().includes(q) ||
				c.username.toLowerCase().includes(q) ||
				(c.url?.toLowerCase().includes(q) ?? false)
			);
		})
	);

	function updatePartitionCount() {
		partitions = partitions.map((p) =>
			p.id === currentPartition ? { ...p, passwordCount: credentials.length } : p
		);
	}

	return {
		get status() {
			return status;
		},
		set status(v) {
			status = v;
		},
		get credentials() {
			return credentials;
		},
		set credentials(v) {
			credentials = v;
		},
		get currentPartition() {
			return currentPartition;
		},
		set currentPartition(v) {
			currentPartition = v;
		},
		get partitions() {
			return partitions;
		},
		set partitions(v) {
			partitions = v;
		},
		get isLoading() {
			return isLoading;
		},
		set isLoading(v) {
			isLoading = v;
		},
		get error() {
			return error;
		},
		set error(v) {
			error = v;
		},
		get searchQuery() {
			return searchQuery;
		},
		set searchQuery(v) {
			searchQuery = v;
		},
		get activeView() {
			return activeView;
		},
		set activeView(v) {
			activeView = v;
		},
		get showAddDialog() {
			return showAddDialog;
		},
		set showAddDialog(v) {
			showAddDialog = v;
		},
		get editingCredentialId() {
			return editingCredentialId;
		},
		set editingCredentialId(v) {
			editingCredentialId = v;
		},
		get filteredCredentials() {
			return filteredCredentials;
		},
		updatePartitionCount,
	};
}

export const vaultState = createVaultState();
