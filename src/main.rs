use clap::{Parser, Subcommand};
use vault_core::VaultManager;
use vault_sync::SyncManager;
use vault_azure::{AzureAdAuthenticator, AzureAdConfig, AzureKeyVaultClient};
use vault_enterprise::{
    AuditCategory, AuditLogger, InMemoryAuditSink,
    CreatePartitionRequest, Feature, LicenseManager, PartitionIsolation, PartitionManager,
};
use anyhow::Result;
use std::io::{self, Write};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "plures-vault")]
#[command(about = "Zero-trust P2P password manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    #[arg(short, long, default_value = "./vault.db")]
    database: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        #[arg(short, long, default_value = "My Vault")]
        name: String,
    },
    /// Unlock the vault
    Unlock,
    /// Add a new credential
    Add {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        username: Option<String>,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Get a credential
    Get {
        #[arg(short, long)]
        name: String,
    },
    /// List all credentials (names only for security)
    List,
    /// Update a credential
    Update {
        #[arg(short, long)]
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Delete a credential
    Delete {
        #[arg(short, long)]
        name: String,
    },
    /// Start P2P sync server
    StartSync {
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Connect to a peer
    ConnectPeer {
        #[arg(short, long)]
        address: String,
    },
    /// List connected peers
    ListPeers,
    /// Lock the vault
    Lock,
    /// Sync with other devices (placeholder for GUI)
    Sync,
    // ── Azure Key Vault commands ───────────────────────────────────────────────
    /// Configure and test Azure Key Vault connectivity
    AzureKvConnect {
        /// Azure AD tenant ID
        #[arg(long)]
        tenant_id: String,
        /// Azure AD application (client) ID
        #[arg(long)]
        client_id: String,
        /// Azure AD client secret
        #[arg(long)]
        client_secret: String,
        /// Azure Key Vault name (subdomain, e.g. "my-vault")
        #[arg(long)]
        vault_name: String,
    },
    /// List secrets in the connected Azure Key Vault
    AzureKvListSecrets {
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        vault_name: String,
    },
    // ── Enterprise / partition commands ───────────────────────────────────────
    /// Create a new vault partition mapped to an Azure Key Vault
    PartitionCreate {
        #[arg(long)]
        name: String,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        azure_vault_name: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// List all configured vault partitions
    PartitionList,
    // ── License commands ──────────────────────────────────────────────────────
    /// Display the status of the current enterprise license
    LicenseStatus,
}

fn prompt_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    // In a real implementation, you'd use a library like `rpassword` to hide input
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    Ok(password.trim().to_string())
}

fn prompt_optional(prompt: &str) -> Option<String> {
    print!("{} (press Enter to skip): ", prompt);
    io::stdout().flush().ok()?;
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;
    let input = input.trim();
    
    if input.is_empty() {
        None
    } else {
        Some(input.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut vault = VaultManager::new(&cli.database).await?;

    match cli.command {
        Commands::Init { name } => {
            println!("🔐 Initializing Plures Vault: {}", name);
            
            let password = prompt_password("Enter master password: ")?;
            let confirm = prompt_password("Confirm master password: ")?;
            
            if password != confirm {
                return Err(anyhow::anyhow!("Passwords don't match"));
            }
            
            match vault.init_vault(&name, &password).await {
                Ok(metadata) => {
                    println!("✅ Vault '{}' initialized successfully", metadata.name);
                    println!("   Vault ID: {}", metadata.id);
                    println!("   Created: {}", metadata.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                Err(e) => {
                    eprintln!("❌ Failed to initialize vault: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Unlock => {
            println!("🔓 Unlocking vault...");
            let password = prompt_password("Enter master password: ")?;
            
            match vault.unlock_vault(&password).await {
                Ok(metadata) => {
                    println!("✅ Vault '{}' unlocked successfully", metadata.name);
                }
                Err(e) => {
                    eprintln!("❌ Failed to unlock vault: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Add { name, username, password, url, notes } => {
            if !vault.is_unlocked() {
                let master_password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&master_password).await?;
            }
            
            println!("📝 Adding credential: {}", name);
            
            let username = username.or_else(|| prompt_optional("Username"));
            let password = password.unwrap_or_else(|| 
                prompt_password("Password: ").unwrap_or_default()
            );
            let url = url.or_else(|| prompt_optional("URL"));
            let notes = notes.or_else(|| prompt_optional("Notes"));
            
            match vault.add_credential(name.clone(), username, password, url, notes).await {
                Ok(credential) => {
                    println!("✅ Credential '{}' added successfully", name);
                    println!("   ID: {}", credential.id);
                    println!("   Created: {}", credential.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                Err(e) => {
                    eprintln!("❌ Failed to add credential: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Get { name } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }
            
            println!("🔍 Getting credential: {}", name);
            match vault.get_credential(&name).await? {
                Some(credential) => {
                    println!("📋 Credential: {}", credential.name);
                    if let Some(username) = &credential.username {
                        println!("   Username: {}", username);
                    }
                    println!("   Password: {}", credential.password);
                    if let Some(url) = &credential.url {
                        println!("   URL: {}", url);
                    }
                    if let Some(notes) = &credential.notes {
                        println!("   Notes: {}", notes);
                    }
                    println!("   Created: {}", credential.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                    println!("   Updated: {}", credential.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                None => {
                    println!("❌ Credential '{}' not found", name);
                }
            }
        }
        
        Commands::List => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }
            
            println!("📋 Vault credentials:");
            match vault.list_credentials().await? {
                credentials if credentials.is_empty() => {
                    println!("   (no credentials found)");
                }
                credentials => {
                    for credential in credentials {
                        println!("   • {} {}", credential.name, 
                            if let Some(username) = &credential.username {
                                format!("({})", username)
                            } else {
                                String::new()
                            }
                        );
                    }
                }
            }
        }
        
        Commands::Update { name, username, password, url, notes } => {
            if !vault.is_unlocked() {
                let master_password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&master_password).await?;
            }
            
            println!("✏️  Updating credential: {}", name);
            match vault.update_credential(&name, username, password, url, notes).await? {
                Some(credential) => {
                    println!("✅ Credential '{}' updated successfully", name);
                    println!("   Version: {}", credential.version);
                    println!("   Updated: {}", credential.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                None => {
                    println!("❌ Credential '{}' not found", name);
                }
            }
        }
        
        Commands::Delete { name } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }
            
            print!("Are you sure you want to delete '{}'? (y/N): ", name);
            io::stdout().flush()?;
            let mut confirmation = String::new();
            io::stdin().read_line(&mut confirmation)?;
            
            if confirmation.trim().to_lowercase() != "y" {
                println!("❌ Deletion cancelled");
                return Ok(());
            }
            
            if vault.delete_credential(&name).await? {
                println!("✅ Credential '{}' deleted successfully", name);
            } else {
                println!("❌ Credential '{}' not found", name);
            }
        }

        Commands::StartSync { port } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }

            println!("🚀 Starting P2P sync server on port {}...", port);
            
            // Get vault metadata for sync
            let metadata = vault.get_vault_metadata().await?;
            let mut sync_manager = SyncManager::new(metadata.id);
            
            sync_manager.start_sync_server(port).await?;
            
            println!("✅ P2P sync server running. Press Ctrl+C to stop.");
            
            // Keep the server running
            tokio::signal::ctrl_c().await?;
            println!("\n🔄 Sync server stopped");
        }

        Commands::ConnectPeer { address } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }

            println!("🔗 Connecting to peer: {}", address);
            
            let metadata = vault.get_vault_metadata().await?;
            let mut sync_manager = SyncManager::new(metadata.id);
            
            match sync_manager.connect_to_peer(&address).await {
                Ok(peer) => {
                    println!("✅ Successfully connected to peer: {}", peer.id);
                    println!("   Public Key: {}", peer.public_key);
                    println!("   Last Seen: {}", peer.last_seen.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                Err(e) => {
                    println!("❌ Failed to connect to peer: {}", e);
                }
            }
        }

        Commands::ListPeers => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }

            println!("👥 Connected peers:");
            
            let metadata = vault.get_vault_metadata().await?;
            let sync_manager = SyncManager::new(metadata.id);
            let peers = sync_manager.list_peers().await;
            
            if peers.is_empty() {
                println!("   (no peers connected)");
            } else {
                for peer in peers {
                    println!("   • {} ({})", peer.id, peer.public_key);
                    println!("     Last seen: {}", peer.last_seen.format("%Y-%m-%d %H:%M:%S UTC"));
                    if let Some(address) = &peer.address {
                        println!("     Address: {}", address);
                    }
                }
            }
        }
        
        Commands::Lock => {
            vault.lock();
            println!("🔒 Vault locked");
        }
        
        Commands::Sync => {
            println!("🔄 Syncing with other devices...");
            println!("💡 Use 'start-sync' to run P2P server, or 'connect-peer' to connect to another device");
        }

        // ── Azure Key Vault commands ───────────────────────────────────────────
        Commands::AzureKvConnect {
            tenant_id,
            client_id,
            client_secret,
            vault_name,
        } => {
            println!("☁️  Testing Azure Key Vault connectivity...");
            println!("   Vault : {}.vault.azure.net", vault_name);
            println!("   Tenant: {}", tenant_id);

            let config = AzureAdConfig {
                tenant_id,
                client_id,
                client_secret,
            };

            match AzureAdAuthenticator::new(config) {
                Ok(auth) => match AzureKeyVaultClient::new(&vault_name, auth) {
                    Ok(client) => {
                        // Attempt to list secrets as a connectivity smoke-test
                        match client.list_secrets().await {
                            Ok(secrets) => {
                                println!("✅ Successfully connected to Azure Key Vault");
                                println!("   {} secret(s) found", secrets.len());
                            }
                            Err(e) => {
                                eprintln!("❌ Connection failed: {}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Client configuration error: {}", e);
                        std::process::exit(1);
                    }
                },
                Err(e) => {
                    eprintln!("❌ Authentication configuration error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::AzureKvListSecrets {
            tenant_id,
            client_id,
            client_secret,
            vault_name,
        } => {
            println!("📋 Listing Azure Key Vault secrets...");

            let config = AzureAdConfig {
                tenant_id,
                client_id,
                client_secret,
            };

            let auth = AzureAdAuthenticator::new(config)
                .map_err(|e| anyhow::anyhow!("Auth config error: {}", e))?;
            let client = AzureKeyVaultClient::new(&vault_name, auth)
                .map_err(|e| anyhow::anyhow!("Client error: {}", e))?;

            match client.list_secrets().await {
                Ok(secrets) if secrets.is_empty() => {
                    println!("   (no secrets found)");
                }
                Ok(secrets) => {
                    for s in secrets {
                        let status = if s.enabled { "enabled" } else { "disabled" };
                        println!("   • {} [{}]", s.name, status);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to list secrets: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // ── Enterprise / partition commands ───────────────────────────────────
        Commands::PartitionCreate {
            name,
            tenant_id,
            azure_vault_name,
            description,
        } => {
            // In a full implementation the max_partitions comes from
            // LicenseManager; here we demonstrate with a generous default.
            let mut mgr = PartitionManager::new(100);
            let req = CreatePartitionRequest {
                name: name.clone(),
                description,
                tenant_id,
                azure_vault_name: azure_vault_name.clone(),
                isolation: PartitionIsolation::Full,
                tags: HashMap::new(),
            };

            match mgr.create_partition(req) {
                Ok(partition) => {
                    println!("✅ Partition '{}' created", partition.name);
                    println!("   ID    : {}", partition.id);
                    println!("   Status: {:?}", partition.status);
                    if let Some(vault) = partition.azure_vault_name {
                        println!("   Vault : {}.vault.azure.net", vault);
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to create partition: {}", e);
                    std::process::exit(1);
                }
            }
        }

        Commands::PartitionList => {
            let mgr = PartitionManager::new(100);
            let partitions = mgr.list_partitions();
            if partitions.is_empty() {
                println!("   (no partitions configured)");
            } else {
                for p in partitions {
                    println!(
                        "   • {} [{:?}]{}",
                        p.name,
                        p.status,
                        p.azure_vault_name
                            .as_deref()
                            .map(|v| format!(" → {}.vault.azure.net", v))
                            .unwrap_or_default()
                    );
                }
            }
        }

        // ── License commands ──────────────────────────────────────────────────
        Commands::LicenseStatus => {
            let mut audit = AuditLogger::new().add_sink(InMemoryAuditSink::new(50));
            let mgr = LicenseManager::new(vec![]);

            let _ = audit.log_success(
                "cli",
                AuditCategory::LicenseManagement,
                "license_status",
                "License status queried from CLI",
            );

            if mgr.is_licensed() {
                println!("✅ Enterprise license: ACTIVE");
                println!("   Tier : {:?}", mgr.effective_tier());
                let features = mgr.effective_features();
                println!("   Features enabled: {}", features.len());
                if mgr.is_feature_enabled(&Feature::AzureKeyVaultSync) {
                    println!("   ✓ Azure Key Vault Sync");
                }
                if mgr.is_feature_enabled(&Feature::MultiPartition) {
                    println!("   ✓ Multi-Partition");
                }
                if mgr.is_feature_enabled(&Feature::AuditLogging) {
                    println!("   ✓ Audit Logging");
                }
                if mgr.is_feature_enabled(&Feature::AzureAdSso) {
                    println!("   ✓ Azure AD SSO");
                }
            } else {
                println!("ℹ️  License status: Community (no enterprise license loaded)");
                println!("   Azure Key Vault sync and enterprise features require a license.");
                println!("   Contact sales@plures.ai to upgrade.");
            }
        }
    }

    Ok(())
}