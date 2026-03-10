<script lang="ts">
	let isUnlocked = false;
	let currentPartition = 'personal';
	let searchQuery = '';
	let masterPassword = '';
	
	// Mock data for development - will connect to Rust backend
	let partitions = [
		{ id: 'personal', name: 'Personal', type: 'local', passwordCount: 42 },
		{ id: 'work', name: 'Work', type: 'azure-kv', passwordCount: 28 }
	];
	
	let passwords = [
		{ id: '1', title: 'GitHub', username: 'user@example.com', url: 'github.com', partition: 'personal' },
		{ id: '2', title: 'Gmail', username: 'user@gmail.com', url: 'gmail.com', partition: 'personal' },
		{ id: '3', title: 'Work Portal', username: 'employee', url: 'company.portal.com', partition: 'work' }
	];
	
	function handleUnlock() {
		if (masterPassword.trim()) {
			isUnlocked = true;
		}
	}
	
	function handlePartitionChange(partition: string) {
		currentPartition = partition;
	}
	
	$: filteredPasswords = passwords.filter(p => 
		p.partition === currentPartition && 
		(p.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
		 p.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
		 p.url.toLowerCase().includes(searchQuery.toLowerCase()))
	);
</script>

<main class="vault-container">
	{#if !isUnlocked}
		<div class="unlock-screen">
			<div class="unlock-dialog">
				<h1>🔐 Plures Vault</h1>
				<p>Enter your master password to unlock your vault</p>
				
				<input
					bind:value={masterPassword}
					type="password"
					placeholder="Master password"
					class="password-input"
					on:keydown={(e) => e.key === 'Enter' && handleUnlock()}
				/>
				
				<button class="unlock-btn" on:click={handleUnlock} disabled={!masterPassword.trim()}>
					Unlock Vault
				</button>
				
				<p class="security-note">
					<strong>Zero-knowledge security:</strong> Your master password never leaves this device.
				</p>
			</div>
		</div>
	{:else}
		<div class="vault-sidebar">
			<div class="sidebar-header">
				<h1>Plures Vault</h1>
				<p>Zero-Trust Password Manager</p>
			</div>
			
			<div class="partitions">
				<h3>Partitions</h3>
				{#each partitions as partition}
					<button
						class="partition-btn"
						class:active={partition.id === currentPartition}
						on:click={() => handlePartitionChange(partition.id)}
					>
						<div>
							<div class="partition-name">{partition.name}</div>
							<div class="partition-type">{partition.type === 'azure-kv' ? '🔐 Azure KV' : '🏠 Local'}</div>
						</div>
						<span class="count">{partition.passwordCount}</span>
					</button>
				{/each}
			</div>
		</div>
		
		<div class="vault-main">
			<div class="toolbar">
				<input
					bind:value={searchQuery}
					placeholder="Search passwords..."
					class="search-input"
				/>
				<button class="add-btn">+ Add Password</button>
			</div>
			
			<div class="passwords-grid">
				{#each filteredPasswords as password}
					<div class="password-card">
						<div class="card-header">
							<h3>{password.title}</h3>
							<div class="actions">
								<button>📋</button>
								<button>✏️</button>
								<button>🗑️</button>
							</div>
						</div>
						<div class="card-body">
							<div class="field">
								<label>Username:</label>
								<span>{password.username}</span>
							</div>
							<div class="field">
								<label>Password:</label>
								<span>••••••••••••</span>
							</div>
							<div class="field">
								<label>URL:</label>
								<a href={`https://${password.url}`} target="_blank">{password.url}</a>
							</div>
						</div>
					</div>
				{:else}
					<div class="empty-state">
						<h3>No passwords found</h3>
						<p>Add your first password to get started</p>
						<button class="add-btn">Add Password</button>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</main>

<style>
	.vault-container {
		display: grid;
		grid-template-columns: 250px 1fr;
		height: 100vh;
		background: #0a0a0a;
		color: #ffffff;
		font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
	}
	
	.unlock-screen {
		grid-column: 1 / -1;
		display: flex;
		align-items: center;
		justify-content: center;
		background: #0a0a0a;
	}
	
	.unlock-dialog {
		background: #1a1a1a;
		padding: 2rem;
		border-radius: 12px;
		border: 1px solid #333;
		max-width: 400px;
		text-align: center;
	}
	
	.unlock-dialog h1 {
		margin: 0 0 0.5rem 0;
		font-size: 1.5rem;
	}
	
	.password-input {
		width: 100%;
		padding: 0.75rem;
		background: #2a2a2a;
		border: 1px solid #444;
		border-radius: 6px;
		color: white;
		margin: 1rem 0;
	}
	
	.unlock-btn {
		width: 100%;
		padding: 0.75rem;
		background: #3b82f6;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		margin-bottom: 1rem;
	}
	
	.unlock-btn:disabled {
		background: #555;
		cursor: not-allowed;
	}
	
	.security-note {
		font-size: 0.8rem;
		color: #888;
		margin: 0;
	}
	
	.vault-sidebar {
		background: #1a1a1a;
		border-right: 1px solid #333;
		padding: 1rem;
	}
	
	.sidebar-header h1 {
		margin: 0 0 0.25rem 0;
		font-size: 1.2rem;
	}
	
	.sidebar-header p {
		margin: 0 0 2rem 0;
		font-size: 0.8rem;
		color: #888;
	}
	
	.partitions h3 {
		margin: 0 0 1rem 0;
		font-size: 0.9rem;
		color: #ccc;
	}
	
	.partition-btn {
		display: flex;
		justify-content: space-between;
		align-items: center;
		width: 100%;
		padding: 0.75rem;
		background: transparent;
		border: 1px solid #333;
		border-radius: 6px;
		color: white;
		cursor: pointer;
		margin-bottom: 0.5rem;
		transition: all 0.2s;
	}
	
	.partition-btn:hover {
		background: #2a2a2a;
	}
	
	.partition-btn.active {
		background: #3b82f6;
		border-color: #3b82f6;
	}
	
	.partition-name {
		font-weight: 600;
		font-size: 0.9rem;
	}
	
	.partition-type {
		font-size: 0.7rem;
		opacity: 0.7;
	}
	
	.count {
		background: #333;
		padding: 0.25rem 0.5rem;
		border-radius: 12px;
		font-size: 0.7rem;
		font-weight: bold;
	}
	
	.vault-main {
		padding: 1.5rem;
		overflow-y: auto;
	}
	
	.toolbar {
		display: flex;
		gap: 1rem;
		margin-bottom: 2rem;
	}
	
	.search-input {
		flex: 1;
		padding: 0.75rem;
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 6px;
		color: white;
	}
	
	.add-btn {
		padding: 0.75rem 1.5rem;
		background: #10b981;
		color: white;
		border: none;
		border-radius: 6px;
		cursor: pointer;
		font-weight: 600;
	}
	
	.passwords-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
		gap: 1rem;
	}
	
	.password-card {
		background: #1a1a1a;
		border: 1px solid #333;
		border-radius: 8px;
		padding: 1rem;
		transition: border-color 0.2s;
	}
	
	.password-card:hover {
		border-color: #555;
	}
	
	.card-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}
	
	.card-header h3 {
		margin: 0;
		font-size: 1.1rem;
	}
	
	.actions {
		display: flex;
		gap: 0.5rem;
	}
	
	.actions button {
		background: transparent;
		border: none;
		color: #888;
		cursor: pointer;
		padding: 0.25rem;
		border-radius: 4px;
		transition: color 0.2s;
	}
	
	.actions button:hover {
		color: white;
	}
	
	.card-body {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	
	.field {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	
	.field label {
		font-size: 0.8rem;
		color: #888;
		min-width: 80px;
	}
	
	.field span {
		font-family: 'Monaco', 'Menlo', monospace;
		font-size: 0.9rem;
	}
	
	.field a {
		color: #3b82f6;
		text-decoration: none;
	}
	
	.field a:hover {
		text-decoration: underline;
	}
	
	.empty-state {
		grid-column: 1 / -1;
		text-align: center;
		padding: 3rem;
		color: #888;
	}
	
	.empty-state h3 {
		margin: 0 0 0.5rem 0;
		color: white;
	}
	
	.empty-state p {
		margin: 0 0 1rem 0;
	}
</style>