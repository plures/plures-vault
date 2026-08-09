import { invoke } from '@tauri-apps/api/core';

export interface CredentialData {
  id?: string;
  name: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
}

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  vault_name?: string;
}

export interface SyncStatusData {
  running: boolean;
  peer_id: string;
  strategy: string;
  peers_connected: number;
  events_sent: number;
  events_received: number;
  conflicts_detected: number;
  conflicts_resolved: number;
  last_sync: string | null;
}

export interface ConflictData {
  id: string;
  node_id: string;
  local_peer_id: string;
  local_updated_at: string;
  remote_peer_id: string;
  remote_updated_at: string;
  detected_at: string;
  resolved: boolean;
  winner: string | null;
  strategy: string | null;
}

export class VaultAPI {
  private databasePath: string;

  constructor(databasePath: string = './vault.db') {
    this.databasePath = databasePath;
  }

  async checkStatus(): Promise<VaultStatus> {
    return await invoke('check_vault_status', { 
      databasePath: this.databasePath 
    });
  }

  async initialize(vaultName: string, masterPassword: string): Promise<void> {
    return await invoke('initialize_vault', {
      databasePath: this.databasePath,
      vaultName,
      masterPassword
    });
  }

  async unlock(masterPassword: string): Promise<void> {
    return await invoke('unlock_vault', {
      databasePath: this.databasePath,
      masterPassword
    });
  }

  async lock(): Promise<void> {
    return await invoke('lock_vault');
  }

  async addCredential(credential: CredentialData): Promise<string> {
    return await invoke('add_credential', {
      credentialData: credential
    });
  }

  async getCredential(credentialId: string): Promise<CredentialData> {
    return await invoke('get_credential', {
      credentialId
    });
  }

  async listCredentials(): Promise<CredentialData[]> {
    return await invoke('list_credentials');
  }

  async updateCredential(credentialId: string, credential: CredentialData): Promise<void> {
    return await invoke('update_credential', {
      credentialId,
      credentialData: credential
    });
  }

  async deleteCredential(credentialId: string): Promise<void> {
    return await invoke('delete_credential', {
      credentialId
    });
  }

  async getSyncStatus(): Promise<SyncStatusData> {
    return await invoke('get_sync_status');
  }

  async listSyncConflicts(pendingOnly: boolean = false): Promise<ConflictData[]> {
    return await invoke('list_sync_conflicts', { pendingOnly });
  }

  async resolveSyncConflict(conflictId: string, winner: 'local' | 'remote'): Promise<void> {
    return await invoke('resolve_sync_conflict', { conflictId, winner });
  }
}

// Export singleton instance
export const vaultAPI = new VaultAPI();