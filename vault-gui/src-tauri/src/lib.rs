use tauri::{Manager, State};
use vault_core::{VaultManager, Credential};
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

// Application state
pub struct AppState {
    vault_manager: Mutex<Option<VaultManager>>,
    vault_unlocked: Mutex<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CredentialData {
    pub id: Option<String>,
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultStatus {
    pub initialized: bool,
    pub unlocked: bool,
    pub vault_name: Option<String>,
}

#[tauri::command]
async fn check_vault_status(
    state: State<'_, AppState>,
    database_path: String,
) -> Result<VaultStatus, String> {
    let vault_manager = VaultManager::new(&database_path);
    
    match vault_manager.check_initialization().await {
        Ok(metadata) => {
            let unlocked = *state.vault_unlocked.lock().unwrap();
            Ok(VaultStatus {
                initialized: true,
                unlocked,
                vault_name: Some(metadata.name),
            })
        }
        Err(_) => Ok(VaultStatus {
            initialized: false,
            unlocked: false,
            vault_name: None,
        })
    }
}

#[tauri::command]
async fn initialize_vault(
    state: State<'_, AppState>,
    database_path: String,
    vault_name: String,
    master_password: String,
) -> Result<(), String> {
    let mut vault_manager = VaultManager::new(&database_path);
    
    vault_manager.init_vault(&vault_name, &master_password).await
        .map_err(|e| e.to_string())?;
    
    // Store the initialized vault manager
    *state.vault_manager.lock().unwrap() = Some(vault_manager);
    *state.vault_unlocked.lock().unwrap() = true;
    
    Ok(())
}

#[tauri::command]
async fn unlock_vault(
    state: State<'_, AppState>,
    database_path: String,
    master_password: String,
) -> Result<(), String> {
    let mut vault_manager = VaultManager::new(&database_path);
    
    vault_manager.unlock(&master_password).await
        .map_err(|e| e.to_string())?;
    
    // Store the unlocked vault manager
    *state.vault_manager.lock().unwrap() = Some(vault_manager);
    *state.vault_unlocked.lock().unwrap() = true;
    
    Ok(())
}

#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    *state.vault_manager.lock().unwrap() = None;
    *state.vault_unlocked.lock().unwrap() = false;
    Ok(())
}

#[tauri::command]
async fn add_credential(
    state: State<'_, AppState>,
    credential_data: CredentialData,
) -> Result<String, String> {
    let vault_manager_guard = state.vault_manager.lock().unwrap();
    let vault_manager = vault_manager_guard.as_ref()
        .ok_or("Vault not unlocked")?;
    
    let credential = Credential {
        id: uuid::Uuid::new_v4(),
        name: credential_data.name,
        username: credential_data.username,
        password: credential_data.password,
        url: credential_data.url.unwrap_or_default(),
        notes: credential_data.notes.unwrap_or_default(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    
    vault_manager.store_credential(&credential).await
        .map_err(|e| e.to_string())?;
    
    Ok(credential.id.to_string())
}

#[tauri::command]
async fn get_credential(
    state: State<'_, AppState>,
    credential_id: String,
) -> Result<CredentialData, String> {
    let vault_manager_guard = state.vault_manager.lock().unwrap();
    let vault_manager = vault_manager_guard.as_ref()
        .ok_or("Vault not unlocked")?;
    
    let id = uuid::Uuid::parse_str(&credential_id)
        .map_err(|e| format!("Invalid UUID: {}", e))?;
    
    let credential = vault_manager.get_credential(&id).await
        .map_err(|e| e.to_string())?;
    
    Ok(CredentialData {
        id: Some(credential.id.to_string()),
        name: credential.name,
        username: credential.username,
        password: credential.password,
        url: Some(credential.url),
        notes: Some(credential.notes),
    })
}

#[tauri::command]
async fn list_credentials(
    state: State<'_, AppState>,
) -> Result<Vec<CredentialData>, String> {
    let vault_manager_guard = state.vault_manager.lock().unwrap();
    let vault_manager = vault_manager_guard.as_ref()
        .ok_or("Vault not unlocked")?;
    
    let credentials = vault_manager.list_credentials().await
        .map_err(|e| e.to_string())?;
    
    let credential_data: Vec<CredentialData> = credentials.into_iter().map(|c| CredentialData {
        id: Some(c.id.to_string()),
        name: c.name,
        username: c.username,
        password: "••••••••••••".to_string(), // Don't expose passwords in list view
        url: Some(c.url),
        notes: Some(c.notes),
    }).collect();
    
    Ok(credential_data)
}

#[tauri::command]
async fn update_credential(
    state: State<'_, AppState>,
    credential_id: String,
    credential_data: CredentialData,
) -> Result<(), String> {
    let vault_manager_guard = state.vault_manager.lock().unwrap();
    let vault_manager = vault_manager_guard.as_ref()
        .ok_or("Vault not unlocked")?;
    
    let id = uuid::Uuid::parse_str(&credential_id)
        .map_err(|e| format!("Invalid UUID: {}", e))?;
    
    let mut credential = vault_manager.get_credential(&id).await
        .map_err(|e| e.to_string())?;
    
    // Update fields
    credential.name = credential_data.name;
    credential.username = credential_data.username;
    credential.password = credential_data.password;
    credential.url = credential_data.url.unwrap_or_default();
    credential.notes = credential_data.notes.unwrap_or_default();
    credential.updated_at = chrono::Utc::now();
    
    vault_manager.update_credential(&credential).await
        .map_err(|e| e.to_string())?;
    
    Ok(())
}

#[tauri::command]
async fn delete_credential(
    state: State<'_, AppState>,
    credential_id: String,
) -> Result<(), String> {
    let vault_manager_guard = state.vault_manager.lock().unwrap();
    let vault_manager = vault_manager_guard.as_ref()
        .ok_or("Vault not unlocked")?;
    
    let id = uuid::Uuid::parse_str(&credential_id)
        .map_err(|e| format!("Invalid UUID: {}", e))?;
    
    vault_manager.delete_credential(&id).await
        .map_err(|e| e.to_string())?;
    
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState {
        vault_manager: Mutex::new(None),
        vault_unlocked: Mutex::new(false),
    };

    tauri::Builder::default()
        .manage(app_state)
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let window = app.get_webview_window("main").unwrap();
                window.open_devtools();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_vault_status,
            initialize_vault,
            unlock_vault,
            lock_vault,
            add_credential,
            get_credential,
            list_credentials,
            update_credential,
            delete_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}