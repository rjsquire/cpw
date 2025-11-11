# CPW - Clipboard Password Manager: Technical Documentation

This document provides detailed technical documentation for the CPW (Clipboard Password Manager) application, including comprehensive function documentation and library usage explanations.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Structures](#data-structures)
3. [Constants](#constants)
4. [Function Documentation](#function-documentation)
5. [Library Dependencies](#library-dependencies)
6. [Cryptographic Implementation](#cryptographic-implementation)
7. [Security Considerations](#security-considerations)

## Architecture Overview

CPW is a command-line password manager written in Go that provides:
- AES-256-GCM encryption for password storage
- PBKDF2 key derivation for enhanced security
- Lock/unlock functionality for convenience
- Clipboard integration for secure password retrieval
- Master password change capability with automatic re-encryption

## Data Structures

### PasswordEntry

Represents a single password entry in the store.

```go
type PasswordEntry struct {
    ID          int       `json:"id"`
    Description string    `json:"description"`
    Password    string    `json:"password"` // Base64-encoded encrypted password
    CreatedAt   time.Time `json:"created_at"`
}
```

**Fields:**
- `ID`: Unique integer identifier for the password entry
- `Description`: Human-readable description of the password
- `Password`: Base64-encoded encrypted password data
- `CreatedAt`: Timestamp when the entry was created

### PasswordStore

Represents the complete password storage structure.

```go
type PasswordStore struct {
    Entries []PasswordEntry `json:"entries"`
    Salt    []byte          `json:"salt"`
}
```

**Fields:**
- `Entries`: Array of password entries
- `Salt`: Cryptographic salt used for key derivation (32 bytes)

## Constants

```go
const (
    dataFile       = "passwords.dat"  // Main password store filename
    lockFile       = ".unlocked"      // Lock state indicator file
    keyFile        = ".session_key"   // Session key storage file
    keySize        = 32               // AES-256 key size in bytes
    nonceSize      = 12               // GCM nonce size in bytes
    iterations     = 100000           // PBKDF2 iterations for key derivation
    sessionKeySize = 32               // Session key size in bytes
)
```

## Function Documentation

### main()

**Signature:** `func main()`

**Purpose:** Entry point of the application. Parses command-line arguments and dispatches to appropriate handler functions.

**Flow:**
1. Validates command-line argument count
2. Extracts command from `os.Args[1]`
3. Routes to specific function based on command
4. Calls `printUsage()` for invalid commands

**Commands Supported:**
- `add <description>`: Add new password
- `get [index]`: Retrieve password (most recent if no index)
- `list`: List all passwords
- `delete <index>`: Delete password by ID
- `unlock`: Unlock password store
- `lock`: Lock password store
- `status`: Show lock status
- `change-password`: Change master password

**Libraries Used:**
- [`os.Args`](https://pkg.go.dev/os#pkg-variables) - Command-line argument access
- [`strconv.Atoi`](https://pkg.go.dev/strconv#Atoi) - String to integer conversion

---

### printUsage()

**Signature:** `func printUsage()`

**Purpose:** Displays help information about available commands and their usage.

**Output:** Formatted help text to standard output.

**Libraries Used:**
- [`fmt.Println`](https://pkg.go.dev/fmt#Println) - Console output

---

### getDataFilePath()

**Signature:** `func getDataFilePath() string`

**Purpose:** Returns the absolute path to the password data file.

**Logic:**
1. Gets user's home directory using `os.UserHomeDir()`
2. Returns `~/.cpw/passwords.dat` or falls back to `passwords.dat`

**Returns:** Full path to password data file as string

**Libraries Used:**
- [`os.UserHomeDir`](https://pkg.go.dev/os#UserHomeDir) - Get user home directory
- [`filepath.Join`](https://pkg.go.dev/path/filepath#Join) - Cross-platform path construction

---

### ensureDataDir()

**Signature:** `func ensureDataDir() error`

**Purpose:** Creates the application's data directory (`~/.cpw`) if it doesn't exist.

**Logic:**
1. Determines home directory
2. Creates `~/.cpw` directory with permissions 0700 (owner read/write/execute only)

**Returns:** Error if directory creation fails, nil on success

**Libraries Used:**
- [`os.UserHomeDir`](https://pkg.go.dev/os#UserHomeDir) - Get user home directory
- [`os.MkdirAll`](https://pkg.go.dev/os#MkdirAll) - Create directory and parents
- [`filepath.Join`](https://pkg.go.dev/path/filepath#Join) - Path construction

---

### getLockFilePath()

**Signature:** `func getLockFilePath() string`

**Purpose:** Returns the absolute path to the lock state file.

**Returns:** Path to `~/.cpw/.unlocked` file

**Libraries Used:**
- [`os.UserHomeDir`](https://pkg.go.dev/os#UserHomeDir)
- [`filepath.Join`](https://pkg.go.dev/path/filepath#Join)

---

### getKeyFilePath()

**Signature:** `func getKeyFilePath() string`

**Purpose:** Returns the absolute path to the session key file.

**Returns:** Path to `~/.cpw/.session_key` file

**Libraries Used:**
- [`os.UserHomeDir`](https://pkg.go.dev/os#UserHomeDir)
- [`filepath.Join`](https://pkg.go.dev/path/filepath#Join)

---

### isUnlocked()

**Signature:** `func isUnlocked() bool`

**Purpose:** Determines if the password store is currently unlocked.

**Logic:**
1. Checks for existence of both lock file and session key file
2. Both files must exist for unlocked state

**Returns:** `true` if store is unlocked, `false` otherwise

**Libraries Used:**
- [`os.Stat`](https://pkg.go.dev/os#Stat) - File existence check
- [`os.IsNotExist`](https://pkg.go.dev/os#IsNotExist) - Error type check

---

### printSecurityWarning()

**Signature:** `func printSecurityWarning()`

**Purpose:** Displays a colored security warning when the store is unlocked.

**Output:** Yellow warning message with ANSI color codes

**Libraries Used:**
- [`fmt.Println`](https://pkg.go.dev/fmt#Println) - Console output with ANSI colors

---

### getMasterPasswordIfNeeded()

**Signature:** `func getMasterPasswordIfNeeded() ([]byte, error)`

**Purpose:** Returns master password or session key depending on lock state.

**Logic:**
1. If unlocked: reads and returns session key from file
2. If locked: prompts for master password
3. Displays security warning when unlocked

**Returns:** 
- Byte slice containing password/key
- Error if operation fails

**Libraries Used:**
- [`os.ReadFile`](https://pkg.go.dev/os#ReadFile) - File reading
- [`fmt.Errorf`](https://pkg.go.dev/fmt#Errorf) - Error formatting

---

### getMasterPassword()

**Signature:** `func getMasterPassword() ([]byte, error)`

**Purpose:** Prompts user for master password input with hidden typing.

**Logic:**
1. Displays password prompt
2. Reads password using terminal without echo
3. Returns password as byte slice

**Returns:**
- Byte slice containing entered password
- Error if input fails

**Libraries Used:**
- [`fmt.Print`](https://pkg.go.dev/fmt#Print) - Prompt output
- [`term.ReadPassword`](https://pkg.go.dev/golang.org/x/term#ReadPassword) - Hidden password input
- [`syscall.Stdin`](https://pkg.go.dev/syscall#pkg-constants) - Standard input file descriptor

---

### deriveKey()

**Signature:** `func deriveKey(password []byte, salt []byte) []byte`

**Purpose:** Derives a cryptographic key from password and salt using PBKDF2.

**Parameters:**
- `password`: Master password bytes
- `salt`: Cryptographic salt bytes

**Logic:**
1. Uses PBKDF2 with SHA-256 hash function
2. Applies 100,000 iterations for security
3. Generates 32-byte key suitable for AES-256

**Returns:** 32-byte derived key

**Libraries Used:**
- [`pbkdf2.Key`](https://pkg.go.dev/golang.org/x/crypto/pbkdf2#Key) - Key derivation function
- [`crypto/sha256.New`](https://pkg.go.dev/crypto/sha256#New) - SHA-256 hash function

---

### encrypt()

**Signature:** `func encrypt(plaintext string, key []byte) ([]byte, error)`

**Purpose:** Encrypts plaintext using AES-256-GCM authenticated encryption.

**Parameters:**
- `plaintext`: String to encrypt
- `key`: 32-byte encryption key

**Logic:**
1. Creates AES cipher from key
2. Wraps in GCM mode for authenticated encryption
3. Generates random 12-byte nonce
4. Encrypts data with authentication
5. Prepends nonce to ciphertext

**Returns:**
- Byte slice containing nonce + encrypted data
- Error if encryption fails

**Security:** GCM mode provides both confidentiality and authenticity

**Libraries Used:**
- [`aes.NewCipher`](https://pkg.go.dev/crypto/aes#NewCipher) - AES cipher creation
- [`cipher.NewGCM`](https://pkg.go.dev/crypto/cipher#NewGCM) - GCM mode wrapper
- [`io.ReadFull`](https://pkg.go.dev/io#ReadFull) - Secure random number generation
- [`crypto/rand.Reader`](https://pkg.go.dev/crypto/rand#pkg-variables) - Cryptographic random source

---

### decrypt()

**Signature:** `func decrypt(ciphertext []byte, key []byte) (string, error)`

**Purpose:** Decrypts AES-256-GCM encrypted data.

**Parameters:**
- `ciphertext`: Encrypted data (nonce + encrypted bytes)
- `key`: 32-byte decryption key

**Logic:**
1. Validates ciphertext length
2. Extracts nonce from first 12 bytes
3. Creates AES-GCM cipher
4. Decrypts and authenticates data
5. Returns plaintext string

**Returns:**
- Decrypted plaintext string
- Error if decryption/authentication fails

**Security:** GCM mode verifies data integrity and authenticity

**Libraries Used:**
- [`aes.NewCipher`](https://pkg.go.dev/crypto/aes#NewCipher)
- [`cipher.NewGCM`](https://pkg.go.dev/crypto/cipher#NewGCM)
- [`fmt.Errorf`](https://pkg.go.dev/fmt#Errorf)

---

### loadPasswordStore()

**Signature:** `func loadPasswordStore(masterPassword []byte) (*PasswordStore, error)`

**Purpose:** Loads and validates the password store from disk.

**Parameters:**
- `masterPassword`: Master password bytes or session key

**Logic:**
1. Creates new store if file doesn't exist
2. Reads and unmarshals JSON data
3. Handles both locked (derive key) and unlocked (use session key) states
4. Verifies password/key by decrypting first entry
5. Returns validated store

**Returns:**
- Pointer to PasswordStore structure
- Error if loading/validation fails

**Libraries Used:**
- [`os.Stat`](https://pkg.go.dev/os#Stat), [`os.IsNotExist`](https://pkg.go.dev/os#IsNotExist) - File existence
- [`os.ReadFile`](https://pkg.go.dev/os#ReadFile) - File reading
- [`json.Unmarshal`](https://pkg.go.dev/encoding/json#Unmarshal) - JSON parsing
- [`base64.StdEncoding.DecodeString`](https://pkg.go.dev/encoding/base64#Encoding.DecodeString) - Base64 decoding

---

### savePasswordStore()

**Signature:** `func savePasswordStore(store *PasswordStore) error`

**Purpose:** Saves the password store to disk as encrypted JSON.

**Parameters:**
- `store`: Pointer to PasswordStore to save

**Logic:**
1. Ensures data directory exists
2. Marshals store to JSON with indentation
3. Writes to file with restrictive permissions (0600)

**Returns:** Error if save operation fails

**Libraries Used:**
- [`json.MarshalIndent`](https://pkg.go.dev/encoding/json#MarshalIndent) - JSON serialization
- [`os.WriteFile`](https://pkg.go.dev/os#WriteFile) - File writing

---

### addPassword()

**Signature:** `func addPassword(description string)`

**Purpose:** Adds a new password entry to the store.

**Parameters:**
- `description`: Human-readable description of the password

**Logic:**
1. Gets master password or session key
2. Loads existing store
3. Prompts for password to store (hidden input)
4. Encrypts password with derived/session key
5. Creates new entry with unique ID
6. Saves updated store

**Libraries Used:**
- [`term.ReadPassword`](https://pkg.go.dev/golang.org/x/term#ReadPassword) - Hidden password input
- [`base64.StdEncoding.EncodeToString`](https://pkg.go.dev/encoding/base64#Encoding.EncodeToString) - Base64 encoding
- [`time.Now`](https://pkg.go.dev/time#Now) - Current timestamp

---

### getPassword()

**Signature:** `func getPassword(index int)`

**Purpose:** Retrieves and copies a password to the clipboard.

**Parameters:**
- `index`: Password ID to retrieve, or -1 for most recent

**Logic:**
1. Gets master password or session key
2. Loads password store
3. Finds entry by ID or gets most recent
4. Decrypts password
5. Copies to system clipboard
6. Reports success to user

**Libraries Used:**
- [`clipboard.WriteAll`](https://pkg.go.dev/github.com/atotto/clipboard#WriteAll) - Clipboard operations

---

### listPasswords()

**Signature:** `func listPasswords()`

**Purpose:** Displays a formatted list of all stored passwords.

**Logic:**
1. Gets master password or session key
2. Loads password store
3. Displays tabular format with ID, description, and creation date
4. Shows security warning if unlocked

**Output Format:**
```
ID | Description | Created
---|-------------|--------
 1 | Gmail       | 2025-11-11 10:30
```

**Libraries Used:**
- [`time.Format`](https://pkg.go.dev/time#Time.Format) - Date formatting

---

### deletePassword()

**Signature:** `func deletePassword(id int)`

**Purpose:** Deletes a password entry after user confirmation.

**Parameters:**
- `id`: ID of password entry to delete

**Logic:**
1. Gets master password or session key
2. Loads password store
3. Finds entry by ID
4. Prompts for confirmation
5. Removes entry from slice
6. Saves updated store

**Libraries Used:**
- [`bufio.NewReader`](https://pkg.go.dev/bufio#NewReader) - Buffered input reading
- [`strings.TrimSpace`](https://pkg.go.dev/strings#TrimSpace) - String trimming
- [`strings.ToLower`](https://pkg.go.dev/strings#ToLower) - Case conversion

---

### unlockStore()

**Signature:** `func unlockStore()`

**Purpose:** Unlocks the password store for session-based access.

**Logic:**
1. Checks if already unlocked
2. Prompts for master password
3. Validates password by loading store
4. Derives session key from master password + salt
5. Saves session key and lock state to files
6. Displays security warning

**Security:** Session key is derived key, not raw master password

**Libraries Used:**
- [`os.WriteFile`](https://pkg.go.dev/os#WriteFile) - File writing for session storage

---

### lockStore()

**Signature:** `func lockStore()`

**Purpose:** Locks the password store by removing session files.

**Logic:**
1. Checks if currently unlocked
2. Removes lock state file
3. Removes session key file
4. Reports success

**Libraries Used:**
- [`os.Remove`](https://pkg.go.dev/os#Remove) - File deletion

---

### showStatus()

**Signature:** `func showStatus()`

**Purpose:** Displays current lock/unlock status of the password store.

**Output:**
- "Password store status: LOCKED" or "UNLOCKED"
- Security warning if unlocked

---

### changeMasterPassword()

**Signature:** `func changeMasterPassword()`

**Purpose:** Changes master password and re-encrypts all stored passwords.

**Logic:**
1. Always prompts for current master password (ignores unlock state)
2. Validates current password
3. Prompts for new password with confirmation
4. Generates new salt for enhanced security
5. Re-encrypts all passwords with new key
6. Updates store with new salt
7. Locks store for security
8. Shows progress for multiple passwords

**Security Features:**
- Always requires current password
- Generates fresh salt
- Atomic operation (all or nothing)
- Automatically locks after change

**Libraries Used:**
- [`io.ReadFull`](https://pkg.go.dev/io#ReadFull) - Random salt generation

---

### loadPasswordStoreWithMasterPassword()

**Signature:** `func loadPasswordStoreWithMasterPassword(masterPassword []byte) (*PasswordStore, error)`

**Purpose:** Loads password store using actual master password, ignoring unlock state.

**Parameters:**
- `masterPassword`: Actual master password bytes (not session key)

**Logic:**
1. Always derives key from master password + salt
2. Used specifically for password change operations
3. Bypasses unlock state checks

**Returns:**
- Pointer to PasswordStore
- Error if validation fails

**Usage:** Called only by `changeMasterPassword()` to ensure security

## Library Dependencies

### Standard Library

#### Cryptographic Libraries
- **[`crypto/aes`](https://pkg.go.dev/crypto/aes)** - AES encryption implementation
- **[`crypto/cipher`](https://pkg.go.dev/crypto/cipher)** - Cipher mode implementations (GCM)
- **[`crypto/rand`](https://pkg.go.dev/crypto/rand)** - Cryptographically secure random numbers
- **[`crypto/sha256`](https://pkg.go.dev/crypto/sha256)** - SHA-256 hash function

#### Encoding Libraries
- **[`encoding/base64`](https://pkg.go.dev/encoding/base64)** - Base64 encoding for safe binary data storage
- **[`encoding/json`](https://pkg.go.dev/encoding/json)** - JSON serialization for data persistence

#### System Libraries
- **[`os`](https://pkg.go.dev/os)** - Operating system interface (files, directories, arguments)
- **[`syscall`](https://pkg.go.dev/syscall)** - Low-level system calls (stdin file descriptor)
- **[`path/filepath`](https://pkg.go.dev/path/filepath)** - Cross-platform file path manipulation

#### I/O and String Libraries
- **[`bufio`](https://pkg.go.dev/bufio)** - Buffered I/O operations
- **[`fmt`](https://pkg.go.dev/fmt)** - Formatted I/O (printing, error formatting)
- **[`io`](https://pkg.go.dev/io)** - Basic I/O primitives
- **[`strings`](https://pkg.go.dev/strings)** - String manipulation functions
- **[`strconv`](https://pkg.go.dev/strconv)** - String conversion functions
- **[`time`](https://pkg.go.dev/time)** - Time handling and formatting

### Third-Party Libraries

#### golang.org/x/crypto/pbkdf2
- **Purpose:** PBKDF2 key derivation function implementation
- **Documentation:** https://pkg.go.dev/golang.org/x/crypto/pbkdf2
- **Usage:** `pbkdf2.Key(password, salt, iterations, keyLen, hashFunc)`
- **Security:** Provides password-based key derivation with configurable iterations

#### golang.org/x/term
- **Purpose:** Terminal I/O functions, particularly for hidden password input
- **Documentation:** https://pkg.go.dev/golang.org/x/term
- **Usage:** `term.ReadPassword(fd)` - Reads password without echoing to terminal
- **Platform Support:** Cross-platform terminal control

#### github.com/atotto/clipboard
- **Purpose:** Cross-platform clipboard access
- **Documentation:** https://pkg.go.dev/github.com/atotto/clipboard
- **Repository:** https://github.com/atotto/clipboard
- **Usage:** `clipboard.WriteAll(text)` - Copies text to system clipboard
- **Platform Support:** Windows, macOS, Linux with various backend implementations

## Cryptographic Implementation

### Encryption Algorithm: AES-256-GCM

**Algorithm Choice:** AES-256-GCM (Galois/Counter Mode)
- **Key Size:** 256 bits (32 bytes)
- **Nonce Size:** 96 bits (12 bytes)
- **Benefits:** 
  - Authenticated encryption (confidentiality + integrity)
  - Resistance to tampering
  - High performance
  - NIST approved

### Key Derivation: PBKDF2

**Parameters:**
- **Hash Function:** SHA-256
- **Iterations:** 100,000
- **Salt Size:** 256 bits (32 bytes)
- **Output Size:** 256 bits (32 bytes)

**Security Benefits:**
- Resistance to rainbow table attacks (salt)
- Resistance to brute force attacks (iterations)
- Standardized algorithm (RFC 2898)

### Random Number Generation

**Source:** `crypto/rand` package
- **Quality:** Cryptographically secure pseudorandom number generator
- **Usage:** Nonce generation, salt generation
- **Platform:** Uses OS-specific secure random sources

### Data Encoding

**Method:** Base64 encoding
- **Purpose:** Safe storage of binary encrypted data in JSON
- **Standard:** RFC 4648 standard encoding
- **Benefits:** Text-safe representation of binary data

## Security Considerations

### Password Storage
- Master passwords are never stored on disk
- Session keys are derived keys, not raw passwords
- All passwords encrypted with AES-256-GCM
- Base64 encoding prevents JSON corruption

### File Permissions
- Data directory: 0700 (owner only)
- Password file: 0600 (owner read/write only)
- Session files: 0600 (owner read/write only)

### Memory Security
- Passwords cleared from memory when possible
- Session keys stored temporarily in files
- No plaintext passwords in variables longer than necessary

### Session Management
- Session keys automatically expire on system restart
- Manual lock functionality for immediate security
- Session key is derived key, not master password
- Lock state validated by file existence

### Master Password Changes
- Always requires current master password verification
- Generates new salt for enhanced security
- Re-encrypts all data atomically
- Automatically locks store after change
- Progress indication for user feedback

### Error Handling
- Generic error messages to prevent information leakage
- Secure cleanup on operation failures
- Validation of all cryptographic operations
- Graceful handling of corrupted data

This documentation provides comprehensive coverage of the CPW application's technical implementation, security model, and library usage for developers and security auditors.