# Update Function Documentation

## updatePassword()

**Signature:** `func updatePassword(id int)`

**Purpose:** Updates the password for an existing password entry.

**Parameters:**
- `id`: Integer ID of the password entry to update

**Logic:**
1. Gets master password or session key using `getMasterPasswordIfNeeded()`
2. Loads the password store
3. Finds the entry with the specified ID
4. Prompts user for new password (hidden input)
5. Validates that password is not empty
6. Encrypts the new password with appropriate key (session key if unlocked, or derived key if locked)
7. Updates the entry in the store
8. Saves the updated store
9. Displays success message and security warning if unlocked

**Error Handling:**
- Returns error if password entry with given ID is not found
- Validates that new password is not empty
- Handles encryption and save errors gracefully

**Security:**
- Uses hidden password input via `term.ReadPassword()`
- Respects lock/unlock state for key handling
- Shows security warning when store is unlocked

**Usage Example:**
```bash
cpw update 1
# Updating password for: Gmail Account (ID: 1)
# Enter new password: [hidden input]
# Password updated successfully for 'Gmail Account' (ID: 1)
```

**Libraries Used:**
- [`term.ReadPassword`](https://pkg.go.dev/golang.org/x/term#ReadPassword) - Hidden password input
- [`base64.StdEncoding.EncodeToString`](https://pkg.go.dev/encoding/base64#Encoding.EncodeToString) - Base64 encoding
- [`syscall.Stdin`](https://pkg.go.dev/syscall#pkg-constants) - Standard input file descriptor