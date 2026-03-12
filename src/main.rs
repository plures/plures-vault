use clap::{Parser, Subcommand};
use vault_core::VaultManager;
use vault_sync::SyncManager;
use anyhow::Result;
use std::io::{self, Write};

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
    }

    Ok(())
}