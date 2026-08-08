<script lang="ts">
  import { vaultAPI } from '$lib/api';
  import type { SyncStatusData, ConflictData } from '$lib/api';

  let syncStatus: SyncStatusData | null = $state(null);
  let conflicts: ConflictData[] = $state([]);
  let showPendingOnly = $state(true);
  let loading = $state(false);
  let error: string | null = $state(null);

  async function refreshStatus() {
    loading = true;
    error = null;
    try {
      syncStatus = await vaultAPI.getSyncStatus();
      conflicts = await vaultAPI.listSyncConflicts(showPendingOnly);
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  async function resolveConflict(conflictId: string, winner: 'local' | 'remote') {
    try {
      await vaultAPI.resolveSyncConflict(conflictId, winner);
      await refreshStatus();
    } catch (e) {
      error = String(e);
    }
  }

  function formatDate(iso: string | null): string {
    if (!iso) return 'Never';
    return new Date(iso).toLocaleString();
  }

  $effect(() => {
    refreshStatus();
  });
</script>

<section class="sync-panel" role="region" aria-label="P2P Sync Status">
  <h2>P2P Sync</h2>

  {#if loading}
    <p class="sync-loading">Loading sync status…</p>
  {:else if error}
    <p class="sync-error" role="alert">{error}</p>
  {:else if syncStatus}
    <div class="sync-status-grid">
      <div class="status-item">
        <span class="status-label">Status</span>
        <span class="status-value" class:running={syncStatus.running}>
          {syncStatus.running ? '● Running' : '○ Stopped'}
        </span>
      </div>
      <div class="status-item">
        <span class="status-label">Peer ID</span>
        <span class="status-value mono">{syncStatus.peer_id.slice(0, 8)}…</span>
      </div>
      <div class="status-item">
        <span class="status-label">Strategy</span>
        <span class="status-value">{syncStatus.strategy}</span>
      </div>
      <div class="status-item">
        <span class="status-label">Peers</span>
        <span class="status-value">{syncStatus.peers_connected}</span>
      </div>
      <div class="status-item">
        <span class="status-label">Sent / Received</span>
        <span class="status-value">{syncStatus.events_sent} / {syncStatus.events_received}</span>
      </div>
      <div class="status-item">
        <span class="status-label">Conflicts</span>
        <span class="status-value">
          {syncStatus.conflicts_detected} detected, {syncStatus.conflicts_resolved} resolved
        </span>
      </div>
      <div class="status-item">
        <span class="status-label">Last Sync</span>
        <span class="status-value">{formatDate(syncStatus.last_sync)}</span>
      </div>
    </div>
  {/if}

  <div class="conflict-section">
    <div class="conflict-header">
      <h3>Conflicts</h3>
      <label class="filter-toggle">
        <input
          type="checkbox"
          bind:checked={showPendingOnly}
          onchange={refreshStatus}
          aria-label="Show pending conflicts only"
        />
        Pending only
      </label>
      <button
        class="refresh-btn"
        onclick={refreshStatus}
        aria-label="Refresh conflict list"
      >
        ↻ Refresh
      </button>
    </div>

    {#if conflicts.length === 0}
      <p class="no-conflicts">No {showPendingOnly ? 'pending ' : ''}conflicts</p>
    {:else}
      <ul class="conflict-list" role="list">
        {#each conflicts as conflict (conflict.id)}
          <li class="conflict-item" class:resolved={conflict.resolved}>
            <div class="conflict-meta">
              <span class="conflict-status">
                {conflict.resolved ? '✅' : '⚠️'}
              </span>
              <span class="conflict-node">Node: {conflict.node_id}</span>
              <span class="conflict-time">Detected: {formatDate(conflict.detected_at)}</span>
            </div>
            <div class="conflict-versions">
              <div class="version local">
                <strong>Local</strong>
                <span>Peer: {conflict.local_peer_id.slice(0, 8)}…</span>
                <span>Updated: {formatDate(conflict.local_updated_at)}</span>
              </div>
              <div class="version remote">
                <strong>Remote</strong>
                <span>Peer: {conflict.remote_peer_id.slice(0, 8)}…</span>
                <span>Updated: {formatDate(conflict.remote_updated_at)}</span>
              </div>
            </div>
            {#if conflict.resolved}
              <div class="conflict-resolution">
                Resolved: {conflict.winner} wins ({conflict.strategy})
              </div>
            {:else}
              <div class="conflict-actions">
                <button
                  class="resolve-btn local-btn"
                  onclick={() => resolveConflict(conflict.id, 'local')}
                  aria-label="Keep local version for conflict {conflict.id}"
                >
                  Keep Local
                </button>
                <button
                  class="resolve-btn remote-btn"
                  onclick={() => resolveConflict(conflict.id, 'remote')}
                  aria-label="Accept remote version for conflict {conflict.id}"
                >
                  Accept Remote
                </button>
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</section>

<style>
  .sync-panel {
    padding: var(--space-4, 1rem);
  }

  .sync-status-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2, 0.5rem);
    margin-bottom: var(--space-4, 1rem);
  }

  .status-item {
    display: flex;
    flex-direction: column;
    padding: var(--space-2, 0.5rem);
    background: var(--color-surface, #f5f5f5);
    border-radius: var(--radius-sm, 4px);
  }

  .status-label {
    font-size: 0.75rem;
    opacity: 0.7;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .status-value {
    font-weight: 600;
  }

  .status-value.running {
    color: var(--color-success, #22c55e);
  }

  .mono {
    font-family: monospace;
  }

  .conflict-header {
    display: flex;
    align-items: center;
    gap: var(--space-3, 0.75rem);
    margin-bottom: var(--space-2, 0.5rem);
  }

  .conflict-header h3 {
    margin: 0;
    flex: 1;
  }

  .filter-toggle {
    display: flex;
    align-items: center;
    gap: var(--space-1, 0.25rem);
    font-size: 0.875rem;
  }

  .refresh-btn {
    padding: var(--space-1, 0.25rem) var(--space-2, 0.5rem);
    border: 1px solid var(--color-border, #ccc);
    border-radius: var(--radius-sm, 4px);
    background: transparent;
    cursor: pointer;
  }

  .no-conflicts {
    color: var(--color-success, #22c55e);
    font-style: italic;
  }

  .conflict-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: var(--space-2, 0.5rem);
  }

  .conflict-item {
    border: 1px solid var(--color-border, #ccc);
    border-radius: var(--radius-sm, 4px);
    padding: var(--space-3, 0.75rem);
  }

  .conflict-item.resolved {
    opacity: 0.7;
  }

  .conflict-meta {
    display: flex;
    gap: var(--space-2, 0.5rem);
    align-items: center;
    margin-bottom: var(--space-2, 0.5rem);
    font-size: 0.875rem;
  }

  .conflict-versions {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: var(--space-2, 0.5rem);
    margin-bottom: var(--space-2, 0.5rem);
  }

  .version {
    display: flex;
    flex-direction: column;
    padding: var(--space-2, 0.5rem);
    background: var(--color-surface, #f5f5f5);
    border-radius: var(--radius-sm, 4px);
    font-size: 0.8rem;
  }

  .conflict-resolution {
    font-size: 0.875rem;
    font-style: italic;
    color: var(--color-muted, #666);
  }

  .conflict-actions {
    display: flex;
    gap: var(--space-2, 0.5rem);
  }

  .resolve-btn {
    padding: var(--space-1, 0.25rem) var(--space-3, 0.75rem);
    border: none;
    border-radius: var(--radius-sm, 4px);
    cursor: pointer;
    font-weight: 600;
    font-size: 0.875rem;
  }

  .local-btn {
    background: var(--color-primary, #3b82f6);
    color: white;
  }

  .remote-btn {
    background: var(--color-secondary, #8b5cf6);
    color: white;
  }

  .sync-loading {
    font-style: italic;
    opacity: 0.7;
  }

  .sync-error {
    color: var(--color-error, #ef4444);
  }
</style>
