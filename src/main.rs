use clap::{Parser, Subcommand};
use vault_core::VaultManager;
use vault_graph::{SecretGraph, SecretNodeKind, RelationshipType};
use vault_mcp::McpServer;
use vault_sync::SyncManager;
use anyhow::Result;
use std::io::{self, Write};
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "plures-vault")]
#[command(about = "Zero-trust P2P password manager with graph-native secrets and AI-native MCP")]
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
        title: String,
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
        title: String,
    },
    /// List all credentials (names only for security)
    List,
    /// Update a credential
    Update {
        #[arg(short, long)]
        title: String,
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
        title: String,
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
    /// Graph-native secret relationship management
    #[command(subcommand)]
    Graph(GraphCommands),
    /// Start MCP server for AI-native interactions (reads JSON-RPC from stdin)
    McpServe,
}

#[derive(Subcommand)]
enum GraphCommands {
    /// Add a group node to the secret graph
    AddGroup {
        #[arg(short, long)]
        label: String,
    },
    /// Add a tag node to the secret graph
    AddTag {
        #[arg(short, long)]
        label: String,
    },
    /// Link a credential to a group
    LinkGroup {
        /// Credential ID (UUID)
        #[arg(long)]
        credential: String,
        /// Group node ID (UUID)
        #[arg(long)]
        group: String,
    },
    /// Link a credential to a tag
    LinkTag {
        /// Credential ID (UUID)
        #[arg(long)]
        credential: String,
        /// Tag node ID (UUID)
        #[arg(long)]
        tag: String,
    },
    /// Add a dependency between two credentials
    AddDep {
        /// Source credential ID (depends on target)
        #[arg(long)]
        source: String,
        /// Target credential ID (depended upon)
        #[arg(long)]
        target: String,
    },
    /// Show rotation impact analysis for a credential
    Impact {
        /// Credential ID (UUID)
        #[arg(long)]
        credential: String,
    },
    /// Show the full secret graph
    Show,
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
                Ok(config) => {
                    println!("✅ Vault '{}' initialized successfully", config.vault_name);
                    println!("   Created: {}", config.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
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
                Ok(config) => {
                    println!("✅ Vault '{}' unlocked successfully", config.vault_name);
                }
                Err(e) => {
                    eprintln!("❌ Failed to unlock vault: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Add { title, username, password, url, notes } => {
            if !vault.is_unlocked() {
                let master_password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&master_password).await?;
            }
            
            println!("📝 Adding credential: {}", title);
            
            let username = username.or_else(|| prompt_optional("Username"));
            let password = password.unwrap_or_else(|| 
                prompt_password("Password: ").unwrap_or_default()
            );
            let url = url.or_else(|| prompt_optional("URL"));
            let notes = notes.or_else(|| prompt_optional("Notes"));
            
            match vault.add_credential(title.clone(), username, password, url, notes).await {
                Ok(credential) => {
                    println!("✅ Credential '{}' added successfully", title);
                    println!("   ID: {}", credential.id);
                    println!("   Created: {}", credential.created_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                Err(e) => {
                    eprintln!("❌ Failed to add credential: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::Get { title } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }
            
            println!("🔍 Getting credential: {}", title);
            match vault.get_credential(&title).await? {
                Some(credential) => {
                    println!("📋 Credential: {}", credential.title);
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
                    println!("❌ Credential '{}' not found", title);
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
                        println!("   • {} {}", credential.title, 
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
        
        Commands::Update { title, username, password, url, notes } => {
            if !vault.is_unlocked() {
                let master_password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&master_password).await?;
            }
            
            println!("✏️  Updating credential: {}", title);
            match vault.update_credential(&title, username, password, url, notes).await? {
                Some(credential) => {
                    println!("✅ Credential '{}' updated successfully", title);
                    println!("   Updated: {}", credential.updated_at.format("%Y-%m-%d %H:%M:%S UTC"));
                }
                None => {
                    println!("❌ Credential '{}' not found", title);
                }
            }
        }
        
        Commands::Delete { title } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }
            
            print!("Are you sure you want to delete '{}'? (y/N): ", title);
            io::stdout().flush()?;
            let mut confirmation = String::new();
            io::stdin().read_line(&mut confirmation)?;
            
            if confirmation.trim().to_lowercase() != "y" {
                println!("❌ Deletion cancelled");
                return Ok(());
            }
            
            if vault.delete_credential(&title).await? {
                println!("✅ Credential '{}' deleted successfully", title);
            } else {
                println!("❌ Credential '{}' not found", title);
            }
        }

        Commands::StartSync { port } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }

            println!("🚀 Starting P2P sync server on port {}...", port);
            
            let config = vault.get_vault_config().await?;
            let mut sync_manager = SyncManager::new(vault.store(), config.vault_id);
            
            sync_manager.start(port).await?;
            
            println!("✅ P2P sync server running on port {}. Press Ctrl+C to stop.", port);
            println!("   Peer ID: {}", sync_manager.local_peer_id());
            
            // Keep the server running
            tokio::signal::ctrl_c().await?;
            sync_manager.stop().await?;
            println!("\n🔄 Sync server stopped");
        }

        Commands::ConnectPeer { address } => {
            if !vault.is_unlocked() {
                let password = prompt_password("Enter master password to unlock vault: ")?;
                vault.unlock_vault(&password).await?;
            }

            println!("🔗 Connecting to peer: {}", address);
            
            let config = vault.get_vault_config().await?;
            let mut sync_manager = SyncManager::new(vault.store(), config.vault_id);
            
            match sync_manager.connect_peer(&address).await {
                Ok(peer) => {
                    println!("✅ Connected to peer: {}", peer.id);
                    println!("   Address: {}", peer.address);
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

            let config = vault.get_vault_config().await?;
            let sync_manager = SyncManager::new(vault.store(), config.vault_id);
            let stats = sync_manager.stats().await;
            
            println!("👥 Sync status:");
            println!("   Running: {}", sync_manager.is_running());
            println!("   Peer ID: {}", sync_manager.local_peer_id());
            println!("   Peers connected: {}", stats.peers_connected);
            println!("   Events sent: {}", stats.events_sent);
            println!("   Events received: {}", stats.events_received);
            if let Some(last) = stats.last_sync {
                println!("   Last sync: {}", last.format("%Y-%m-%d %H:%M:%S UTC"));
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

        Commands::Graph(graph_cmd) => {
            // Load or create graph state
            let graph_path = format!("{}.graph.json", cli.database);
            let mut graph = load_graph(&graph_path);

            match graph_cmd {
                GraphCommands::AddGroup { label } => {
                    let node = graph.add_node(SecretNodeKind::Group, &label);
                    println!("✅ Group '{}' created", label);
                    println!("   ID: {}", node.id);
                }
                GraphCommands::AddTag { label } => {
                    let node = graph.add_node(SecretNodeKind::Tag, &label);
                    println!("✅ Tag '{}' created", label);
                    println!("   ID: {}", node.id);
                }
                GraphCommands::LinkGroup { credential, group } => {
                    let cred_id = Uuid::parse_str(&credential)
                        .map_err(|e| anyhow::anyhow!("Invalid credential UUID: {}", e))?;
                    let group_id = Uuid::parse_str(&group)
                        .map_err(|e| anyhow::anyhow!("Invalid group UUID: {}", e))?;

                    // Ensure credential node exists in graph
                    if graph.get_node(&cred_id).is_none() {
                        graph.add_node_with_id(cred_id, SecretNodeKind::Credential, &credential);
                    }

                    match graph.add_edge(cred_id, group_id, RelationshipType::GroupMember) {
                        Ok(_) => println!("✅ Credential linked to group"),
                        Err(e) => println!("❌ Failed to link: {}", e),
                    }
                }
                GraphCommands::LinkTag { credential, tag } => {
                    let cred_id = Uuid::parse_str(&credential)
                        .map_err(|e| anyhow::anyhow!("Invalid credential UUID: {}", e))?;
                    let tag_id = Uuid::parse_str(&tag)
                        .map_err(|e| anyhow::anyhow!("Invalid tag UUID: {}", e))?;

                    if graph.get_node(&cred_id).is_none() {
                        graph.add_node_with_id(cred_id, SecretNodeKind::Credential, &credential);
                    }

                    match graph.add_edge(cred_id, tag_id, RelationshipType::TaggedWith) {
                        Ok(_) => println!("✅ Credential tagged"),
                        Err(e) => println!("❌ Failed to tag: {}", e),
                    }
                }
                GraphCommands::AddDep { source, target } => {
                    let source_id = Uuid::parse_str(&source)
                        .map_err(|e| anyhow::anyhow!("Invalid source UUID: {}", e))?;
                    let target_id = Uuid::parse_str(&target)
                        .map_err(|e| anyhow::anyhow!("Invalid target UUID: {}", e))?;

                    if graph.get_node(&source_id).is_none() {
                        graph.add_node_with_id(source_id, SecretNodeKind::Credential, &source);
                    }
                    if graph.get_node(&target_id).is_none() {
                        graph.add_node_with_id(target_id, SecretNodeKind::Credential, &target);
                    }

                    match graph.add_edge(source_id, target_id, RelationshipType::DependsOn) {
                        Ok(_) => println!("✅ Dependency added: {} → {}", source, target),
                        Err(e) => println!("❌ Failed to add dependency: {}", e),
                    }
                }
                GraphCommands::Impact { credential } => {
                    let cred_id = Uuid::parse_str(&credential)
                        .map_err(|e| anyhow::anyhow!("Invalid credential UUID: {}", e))?;

                    let impacted = graph.rotation_impact(&cred_id);
                    if impacted.is_empty() {
                        println!("✅ No other credentials depend on {}", credential);
                    } else {
                        println!("⚠️  Rotation impact for {}:", credential);
                        for node in impacted {
                            println!("   • {} ({})", node.label, node.id);
                        }
                    }
                }
                GraphCommands::Show => {
                    let nodes = graph.list_nodes();
                    let edge_count = graph.edge_count();
                    println!("📊 Secret Graph: {} nodes, {} edges", nodes.len(), edge_count);
                    println!();
                    for node in &nodes {
                        println!("  [{:?}] {} ({})", node.kind, node.label, node.id);
                        let edges = graph.get_edges_from(&node.id);
                        for edge in edges {
                            if let Some(target) = graph.get_node(&edge.target) {
                                println!("    → {:?} → {} ({})", edge.relationship, target.label, target.id);
                            }
                        }
                    }
                }
            }

            save_graph(&graph, &graph_path)?;
        }

        Commands::McpServe => {
            println!("🤖 Starting MCP server (reading JSON-RPC from stdin)...");
            println!("   Send JSON-RPC requests, one per line. Ctrl+D to exit.");

            let mut server = McpServer::new();
            let mut input = String::new();
            
            loop {
                input.clear();
                match io::stdin().read_line(&mut input) {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        let trimmed = input.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        match server.handle_message(trimmed) {
                            Ok(response) => println!("{}", response),
                            Err(e) => eprintln!("MCP error: {}", e),
                        }
                    }
                    Err(e) => {
                        eprintln!("Read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

fn load_graph(path: &str) -> SecretGraph {
    match std::fs::read_to_string(path) {
        Ok(json) => SecretGraph::from_json(&json).unwrap_or_default(),
        Err(_) => SecretGraph::new(),
    }
}

fn save_graph(graph: &SecretGraph, path: &str) -> Result<()> {
    let json = graph.to_json().map_err(|e| anyhow::anyhow!("Failed to serialize graph: {}", e))?;
    std::fs::write(path, json)?;
    Ok(())
}