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

## How It Works

1. **Master Password**: You set a master password that protects all your stored passwords
2. **Encryption**: Each password is encrypted using AES-256-GCM with a key derived from your master password using PBKDF2
3. **Storage**: Encrypted passwords are stored in `~/.cpw/passwords.dat`
4. **Retrieval**: When you retrieve a password, it's decrypted and copied to your clipboard automatically

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
# Add some passwords
cpw add "GitHub"
cpw add "Work Email"
cpw add "Bank Account"

# List all passwords
cpw list

# Get the most recent password (Bank Account)
cpw get

# Get a specific password by ID
cpw get 1  # Gets GitHub password

# Delete a password
cpw delete 2  # Deletes Work Email password
```

## Security Notes

- Choose a strong master password - it protects all your other passwords
- The clipboard is cleared automatically after copying (OS dependent)
- Never share your `passwords.dat` file or master password
- Regular backups of `passwords.dat` are recommended (the file is encrypted)

## Dependencies

- `golang.org/x/crypto` - For PBKDF2 key derivation
- `golang.org/x/term` - For secure password input
- `github.com/atotto/clipboard` - For clipboard operations
