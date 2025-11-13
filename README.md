# CPW - Clipboard Password Manager

A secure command-line password manager that stores encrypted passwords and copies them to your clipboard for easy pasting.

## Features

- **Secure Encryption**: Uses AES-256-GCM encryption with PBKDF2 key derivation
- **Master Password Protection**: All passwords are protected by a single master password
- **Clipboard Integration**: Automatically copies decrypted passwords to your clipboard
- **Simple CLI Interface**: Easy-to-use command-line interface
- **Cross-platform**: Works on macOS, Linux, and Windows

## Installation

```bash
go build -o cpw main.go
```

Or install directly:
```bash
go install
```

## Usage

### Add a Password
```bash
cpw add "Gmail Account"
# You'll be prompted for your master password and the password to store
```

### Retrieve a Password
```bash
# Get the most recent password
cpw get

# Get a specific password by ID
cpw get 1

# Shortcut: Get password by ID (no 'get' command needed)
cpw 1
```

### Update a Password
```bash
# Update an existing password by ID
cpw update 1
# You'll be prompted for the new password
```

### List All Passwords
```bash
cpw list
# Shows ID, description, and creation date for all stored passwords
```

### Delete a Password
```bash
cpw delete 1
# Deletes the password with ID 1 (with confirmation prompt)
```

### Lock and Unlock Store
```bash
# Unlock the password store (requires master password)
cpw unlock

# Check lock status
cpw status

# Lock the password store (no password required)
cpw lock
```

### Change Master Password
```bash
# Change the master password (requires current password even if unlocked)
cpw change-password
# You'll be prompted for:
# 1. Current master password
# 2. New master password  
# 3. Confirmation of new password
```

## How It Works

1. **Master Password**: You set a master password that protects all your stored passwords
2. **Encryption**: Each password is encrypted using AES-256-GCM with a key derived from your master password using PBKDF2
3. **Storage**: Encrypted passwords are stored in `~/.cpw/passwords.dat`
4. **Lock/Unlock**: You can unlock the store to avoid entering your master password repeatedly
5. **Retrieval**: When you retrieve a password, it's decrypted and copied to your clipboard automatically

## Security Features

- **Strong Encryption**: AES-256-GCM provides authenticated encryption
- **Key Derivation**: PBKDF2 with 100,000 iterations protects against brute force attacks
- **Secure Storage**: Password file is stored with restrictive permissions (0600)
- **No Plaintext**: Passwords are never stored in plaintext on disk
- **Memory Safety**: Passwords are only decrypted temporarily for clipboard copying

## File Locations

- **macOS/Linux**: `~/.cpw/passwords.dat`
- **Windows**: `%USERPROFILE%\.cpw\passwords.dat`

## Example Workflow

```bash
# Add some passwords (requires master password each time when locked)
cpw add "GitHub"
cpw add "Work Email" 
cpw add "Bank Account"

# For frequent use, unlock the store
cpw unlock
# Enter master password once

# Now use commands without entering master password
cpw list
cpw 1         # Shortcut to get password with ID 1
cpw add "Another Account"
cpw update 2  # Update Work Email password

# Lock when done for security
cpw lock

# Change master password if needed
cpw change-password
# Enter current master password: [hidden]
# Enter new master password: [hidden]  
# Confirm new master password: [hidden]
# Changing master password and re-encrypting all stored passwords...
# Master password changed successfully. All X passwords have been re-encrypted.
```

## Lock/Unlock Feature

- **Locked State** (default): Requires master password for every operation
- **Unlocked State**: Master password entered once, then cached for subsequent operations
- **Security Warning**: When unlocked, all commands show a warning reminder to lock the store
- **Session Management**: Unlock state is maintained until you run `cpw lock` or restart your system

## Convenience Features

### Integer Shortcut
- **Quick Access**: Use `cpw 1` instead of `cpw get 1` for faster password retrieval
- **Same Security**: Shortcut respects lock/unlock state and shows security warnings
- **Error Handling**: Invalid IDs show the same clear error messages as the full command

## Change Master Password

- **Security First**: Always requires current master password, even when store is unlocked
- **Re-encryption**: All stored passwords are automatically re-encrypted with the new master password
- **New Salt**: A new cryptographic salt is generated for enhanced security
- **Auto-lock**: Store is automatically locked after password change for security
- **Confirmation**: Requires confirmation of new password to prevent typos

## Security Notes

- Choose a strong master password - it protects all your other passwords
- **Always lock the store** when finished - unlocked stores are a security risk
- The clipboard is cleared automatically after copying (OS dependent)
- Never share your `passwords.dat` file or master password
- Regular backups of `passwords.dat` are recommended (the file is encrypted)
- Session files (`.unlocked`, `.session_key`) are automatically cleaned up when locking
- Unlock state does not persist across system restarts

## Dependencies

- `golang.org/x/crypto` - For PBKDF2 key derivation
- `golang.org/x/term` - For secure password input
- `github.com/atotto/clipboard` - For clipboard operations
