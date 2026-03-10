#!/bin/bash

# Plures Vault Migration Script
# Migrate existing credentials from ~/.openclaw/secure/ to Plures Vault

set -e

VAULT_DB="./vault.db"
SECURE_DIR="$HOME/.openclaw/secure"

echo "🔐 Plures Vault Migration Tool"
echo "==============================="

# Check if secure directory exists
if [ ! -d "$SECURE_DIR" ]; then
    echo "❌ No credentials found at $SECURE_DIR"
    exit 1
fi

echo "📋 Found credentials to migrate:"
ls -la "$SECURE_DIR"

echo ""
echo "⚠️  This will create a new Plures Vault and import your existing credentials."
echo "⚠️  Your original files in $SECURE_DIR will remain unchanged."
echo ""

# Initialize vault (user will set master password)
if [ ! -f "$VAULT_DB" ]; then
    echo "🏗️  Initializing new Plures Vault..."
    cargo run -- init --name "Migrated Vault"
else
    echo "📂 Using existing vault at $VAULT_DB"
fi

echo ""
echo "📦 Migrating credentials..."

# Google API credentials
if [ -f "$SECURE_DIR/credentials.json" ]; then
    echo "   • Google API credentials"
    # Extract client_id as username, client_secret as password
    CLIENT_ID=$(jq -r '.installed.client_id' "$SECURE_DIR/credentials.json")
    CLIENT_SECRET=$(jq -r '.installed.client_secret' "$SECURE_DIR/credentials.json")
    PROJECT_ID=$(jq -r '.installed.project_id' "$SECURE_DIR/credentials.json")
    
    cargo run -- add \
        --name "google-api" \
        --username "$CLIENT_ID" \
        --password "$CLIENT_SECRET" \
        --notes "Google API credentials for project: $PROJECT_ID"
fi

# Gmail tasker credentials  
if [ -f "$SECURE_DIR/gmail-tasker-credentials.json" ]; then
    echo "   • Gmail Tasker credentials"
    CLIENT_ID=$(jq -r '.installed.client_id' "$SECURE_DIR/gmail-tasker-credentials.json")
    CLIENT_SECRET=$(jq -r '.installed.client_secret' "$SECURE_DIR/gmail-tasker-credentials.json")
    
    cargo run -- add \
        --name "gmail-tasker" \
        --username "$CLIENT_ID" \
        --password "$CLIENT_SECRET" \
        --notes "Gmail Tasker API credentials"
fi

# Access tokens
if [ -f "$SECURE_DIR/token.json" ]; then
    echo "   • Google access token"
    ACCESS_TOKEN=$(jq -r '.access_token' "$SECURE_DIR/token.json")
    REFRESH_TOKEN=$(jq -r '.refresh_token // empty' "$SECURE_DIR/token.json")
    
    cargo run -- add \
        --name "google-access-token" \
        --username "oauth2" \
        --password "$ACCESS_TOKEN" \
        --notes "Google OAuth2 access token. Refresh token: $REFRESH_TOKEN"
fi

# Keyring password
if [ -f "$SECURE_DIR/gog-keyring-password.txt" ]; then
    echo "   • GOG keyring password"
    KEYRING_PASSWORD=$(cat "$SECURE_DIR/gog-keyring-password.txt")
    
    cargo run -- add \
        --name "gog-keyring" \
        --username "keyring" \
        --password "$KEYRING_PASSWORD" \
        --notes "GOG keyring password"
fi

echo ""
echo "✅ Migration complete!"
echo ""
echo "🔍 Verify your migrated credentials:"
cargo run -- list

echo ""
echo "🔒 Your vault is now ready. Use these commands:"
echo "   cargo run -- get --name <credential-name>"
echo "   cargo run -- lock    # Lock vault when done"
echo ""
echo "💡 Original files remain at $SECURE_DIR for backup"