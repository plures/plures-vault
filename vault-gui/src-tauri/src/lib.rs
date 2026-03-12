use tauri::{AppHandle, Manager, State};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};
use vault_core::VaultManager;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

// Application state
pub struct AppState {
    vault_database_path: Mutex<Option<String>>,
    vault_unlocked: Mutex<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct CredentialData {
    pub id: Option<String>,
    pub title: String,
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
    _app: AppHandle,
    state: State<'_, AppState>,
    database_path: String,
) -> Result<VaultStatus, String> {
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to initialize vault manager: {}", e))?;

    match vault_manager.check_initialization().await {
        Ok(config) => {
            let unlocked = *state.vault_unlocked.lock().unwrap();
            Ok(VaultStatus {
                initialized: true,
                unlocked,
                vault_name: Some(config.vault_name),
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
    _app: AppHandle,
    state: State<'_, AppState>,
    database_path: String,
    vault_name: String,
    master_password: String,
) -> Result<(), String> {
    let mut vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to initialize vault manager: {}", e))?;

    vault_manager.init_vault(&vault_name, &master_password).await
        .map_err(|e| e.to_string())?;

    // Store the database path and set unlocked status
    *state.vault_database_path.lock().unwrap() = Some(database_path);
    *state.vault_unlocked.lock().unwrap() = true;

    Ok(())
}

#[tauri::command]
async fn unlock_vault(
    _app: AppHandle,
    state: State<'_, AppState>,
    database_path: String,
    master_password: String,
) -> Result<(), String> {
    let mut vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to initialize vault manager: {}", e))?;

    vault_manager.unlock_vault(&master_password).await
        .map_err(|e| e.to_string())?;

    // Store the database path and set unlocked status
    *state.vault_database_path.lock().unwrap() = Some(database_path);
    *state.vault_unlocked.lock().unwrap() = true;

    Ok(())
}

#[tauri::command]
async fn lock_vault(_app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    *state.vault_database_path.lock().unwrap() = None;
    *state.vault_unlocked.lock().unwrap() = false;
    Ok(())
}

#[tauri::command]
async fn add_credential(
    _app: AppHandle,
    state: State<'_, AppState>,
    credential_data: CredentialData,
) -> Result<String, String> {
    // Get the database path
    let database_path = {
        let path_guard = state.vault_database_path.lock().unwrap();
        path_guard.as_ref()
            .ok_or("Vault not initialized")?
            .clone()
    };

    // Check if vault is unlocked
    let is_unlocked = *state.vault_unlocked.lock().unwrap();
    if !is_unlocked {
        return Err("Vault is not unlocked".to_string());
    }

    // Create vault manager and perform operation
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to create vault manager: {}", e))?;

    let credential_id = vault_manager.add_credential(
        credential_data.title,
        if credential_data.username.is_empty() { None } else { Some(credential_data.username) },
        credential_data.password,
        credential_data.url,
        credential_data.notes,
    ).await
        .map_err(|e| e.to_string())?;

    Ok(credential_id.id.to_string())
}

#[tauri::command]
async fn get_credential(
    _app: AppHandle,
    state: State<'_, AppState>,
    credential_id: String,
) -> Result<CredentialData, String> {
    // Get the database path
    let database_path = {
        let path_guard = state.vault_database_path.lock().unwrap();
        path_guard.as_ref()
            .ok_or("Vault not initialized")?
            .clone()
    };

    // Check if vault is unlocked
    let is_unlocked = *state.vault_unlocked.lock().unwrap();
    if !is_unlocked {
        return Err("Vault is not unlocked".to_string());
    }

    // Create vault manager and perform operation
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to create vault manager: {}", e))?;

    let credential = vault_manager.get_credential_by_id(&credential_id).await
        .map_err(|e| e.to_string())?;

    if let Some(credential) = credential {
        Ok(CredentialData {
            id: Some(credential.id.to_string()),
            title: credential.title,
            username: credential.username.unwrap_or_default(),
            password: credential.password,
            url: credential.url,
            notes: credential.notes,
        })
    } else {
        Err("Credential not found".to_string())
    }
}

#[tauri::command]
async fn list_credentials(
    _app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<CredentialData>, String> {
    // Get the database path
    let database_path = {
        let path_guard = state.vault_database_path.lock().unwrap();
        path_guard.as_ref()
            .ok_or("Vault not initialized")?
            .clone()
    };

    // Check if vault is unlocked
    let is_unlocked = *state.vault_unlocked.lock().unwrap();
    if !is_unlocked {
        return Err("Vault is not unlocked".to_string());
    }

    // Create vault manager and perform operation
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to create vault manager: {}", e))?;

    let credentials = vault_manager.list_credentials().await
        .map_err(|e| e.to_string())?;

    let credential_data: Vec<CredentialData> = credentials.into_iter().map(|c| CredentialData {
        id: Some(c.id.to_string()),
        title: c.title,
        username: c.username.unwrap_or_default(),
        password: "••••••••••••".to_string(), // Don't expose passwords in list view
        url: c.url,
        notes: c.notes,
    }).collect();

    Ok(credential_data)
}

#[tauri::command]
async fn update_credential(
    _app: AppHandle,
    state: State<'_, AppState>,
    credential_id: String,
    credential_data: CredentialData,
) -> Result<(), String> {
    // Get the database path
    let database_path = {
        let path_guard = state.vault_database_path.lock().unwrap();
        path_guard.as_ref()
            .ok_or("Vault not initialized")?
            .clone()
    };

    // Check if vault is unlocked
    let is_unlocked = *state.vault_unlocked.lock().unwrap();
    if !is_unlocked {
        return Err("Vault is not unlocked".to_string());
    }

    // Create vault manager and perform operation
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to create vault manager: {}", e))?;

    // Use the VaultManager's update method with individual parameters
    vault_manager.update_credential_by_id(
        &credential_id,
        Some(credential_data.title),
        if credential_data.username.is_empty() { None } else { Some(credential_data.username) },
        Some(credential_data.password),
        credential_data.url,
        credential_data.notes,
    ).await
    .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
async fn delete_credential(
    _app: AppHandle,
    state: State<'_, AppState>,
    credential_id: String,
) -> Result<(), String> {
    // Get the database path
    let database_path = {
        let path_guard = state.vault_database_path.lock().unwrap();
        path_guard.as_ref()
            .ok_or("Vault not initialized")?
            .clone()
    };

    // Check if vault is unlocked
    let is_unlocked = *state.vault_unlocked.lock().unwrap();
    if !is_unlocked {
        return Err("Vault is not unlocked".to_string());
    }

    // Create vault manager and perform operation
    let vault_manager = VaultManager::new(&database_path).await
        .map_err(|e| format!("Failed to create vault manager: {}", e))?;

    vault_manager.delete_credential_by_id(&credential_id).await
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
async fn close_splash(window: tauri::Window) {
    // Close splashscreen
    if let Some(splash) = window.get_webview_window("splash") {
        splash.close().unwrap();
    }
    // Show main window
    if let Some(main) = window.get_webview_window("main") {
        main.show().unwrap();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState {
        vault_database_path: Mutex::new(None),
        vault_unlocked: Mutex::new(false),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized".to_string()])
        ))
        .manage(app_state)
        .setup(|app| {
            let show_i = MenuItem::with_id(app, "show", "Show Plures Vault", true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", "Lock Vault", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .icon(app.default_window_icon().unwrap().clone())
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "lock" => {
                        // Emit event to lock the vault
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.emit("vault-lock-requested", ());
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            // Toggle window visibility on left-click
                            if window.is_visible().unwrap_or(false) {
                                let _ = window.hide();
                            } else {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            close_splash,
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