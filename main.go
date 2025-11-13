package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

type PasswordEntry struct {
	ID          int       `json:"id"`
	Description string    `json:"description"`
	Password    string    `json:"password"` // This will be encrypted
	CreatedAt   time.Time `json:"created_at"`
}

type PasswordStore struct {
	Entries []PasswordEntry `json:"entries"`
	Salt    []byte          `json:"salt"`
}

const (
	dataFile       = "passwords.dat"
	lockFile       = ".unlocked"
	keyFile        = ".session_key"
	keySize        = 32     // AES-256
	nonceSize      = 12     // GCM nonce size
	iterations     = 100000 // PBKDF2 iterations
	sessionKeySize = 32     // Session key size
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	// Check if the command is just a number (shortcut for get)
	if index, err := strconv.Atoi(command); err == nil {
		getPassword(index)
		return
	}

	switch command {
	case "add":
		if len(os.Args) < 3 {
			fmt.Println("Usage: cpw add <description>")
			return
		}
		description := strings.Join(os.Args[2:], " ")
		addPassword(description)
	case "get":
		if len(os.Args) == 2 {
			// Get most recent password
			getPassword(-1)
		} else {
			// Get password by index
			index, err := strconv.Atoi(os.Args[2])
			if err != nil {
				fmt.Printf("Invalid index: %s\n", os.Args[2])
				return
			}
			getPassword(index)
		}
	case "list":
		listPasswords()
	case "delete":
		if len(os.Args) < 3 {
			fmt.Println("Usage: cpw delete <index>")
			return
		}
		index, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid index: %s\n", os.Args[2])
			return
		}
		deletePassword(index)
	case "update":
		if len(os.Args) < 3 {
			fmt.Println("Usage: cpw update <index>")
			return
		}
		index, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Printf("Invalid index: %s\n", os.Args[2])
			return
		}
		updatePassword(index)
	case "unlock":
		unlockStore()
	case "lock":
		lockStore()
	case "status":
		showStatus()
	case "change-password":
		changeMasterPassword()
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("CPW - Clipboard Password Manager")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cpw <index>              - Get password by index (shortcut for 'get')")
	fmt.Println("  cpw add <description>     - Add a new password")
	fmt.Println("  cpw get [index]          - Get password (most recent if no index)")
	fmt.Println("  cpw list                 - List all passwords")
	fmt.Println("  cpw update <index>       - Update an existing password")
	fmt.Println("  cpw delete <index>       - Delete a password")
	fmt.Println("  cpw unlock               - Unlock the password store")
	fmt.Println("  cpw lock                 - Lock the password store")
	fmt.Println("  cpw status               - Show lock status")
	fmt.Println("  cpw change-password      - Change the master password")
}

func getDataFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return dataFile
	}
	return filepath.Join(home, ".cpw", dataFile)
}

func ensureDataDir() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".cpw")
	return os.MkdirAll(dir, 0700)
}

func getLockFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return lockFile
	}
	return filepath.Join(home, ".cpw", lockFile)
}

func getKeyFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return keyFile
	}
	return filepath.Join(home, ".cpw", keyFile)
}

func isUnlocked() bool {
	lockPath := getLockFilePath()
	keyPath := getKeyFilePath()

	// Both lock file and key file must exist
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

func printSecurityWarning() {
	fmt.Println("\033[33m⚠️  WARNING: Password store is UNLOCKED - remember to run 'cpw lock' when done!\033[0m")
}

func getMasterPasswordIfNeeded() ([]byte, error) {
	if isUnlocked() {
		printSecurityWarning()
		// Load session key from file
		keyPath := getKeyFilePath()
		sessionKey, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read session key: %v", err)
		}
		return sessionKey, nil
	}
	return getMasterPassword()
}

func getMasterPassword() ([]byte, error) {
	fmt.Print("Enter master password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, err
	}
	return password, nil
}

func deriveKey(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, iterations, keySize, sha256.New)
}

func encrypt(plaintext string, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func loadPasswordStore(masterPassword []byte) (*PasswordStore, error) {
	filePath := getDataFilePath()

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Create new store with random salt
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		return &PasswordStore{
			Entries: []PasswordEntry{},
			Salt:    salt,
		}, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var store PasswordStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	// If unlocked, masterPassword is actually the session key
	// If locked, masterPassword needs to be derived with salt
	var key []byte
	if isUnlocked() {
		// masterPassword is already the derived session key
		key = masterPassword
	} else {
		// Derive key from master password and salt
		key = deriveKey(masterPassword, store.Salt)
	}

	// Verify password/session by trying to decrypt the first entry
	if len(store.Entries) > 0 {
		encryptedData, err := base64.StdEncoding.DecodeString(store.Entries[0].Password)
		if err != nil {
			return nil, fmt.Errorf("corrupted password data")
		}
		_, err = decrypt(encryptedData, key)
		if err != nil {
			if isUnlocked() {
				return nil, fmt.Errorf("invalid session key")
			} else {
				return nil, fmt.Errorf("invalid master password")
			}
		}
	}

	return &store, nil
}

func savePasswordStore(store *PasswordStore) error {
	if err := ensureDataDir(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	filePath := getDataFilePath()
	return os.WriteFile(filePath, data, 0600)
}

func addPassword(description string) {
	masterPassword, err := getMasterPasswordIfNeeded()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error loading password store: %v\n", err)
		return
	}

	fmt.Print("Enter password to store: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}

	var key []byte
	if isUnlocked() {
		key = masterPassword // masterPassword is already the session key
	} else {
		key = deriveKey(masterPassword, store.Salt)
	}
	encryptedPassword, err := encrypt(string(password), key)
	if err != nil {
		fmt.Printf("Error encrypting password: %v\n", err)
		return
	}

	// Find next ID
	nextID := 1
	for _, entry := range store.Entries {
		if entry.ID >= nextID {
			nextID = entry.ID + 1
		}
	}

	entry := PasswordEntry{
		ID:          nextID,
		Description: description,
		Password:    base64.StdEncoding.EncodeToString(encryptedPassword),
		CreatedAt:   time.Now(),
	}

	store.Entries = append(store.Entries, entry)

	if err := savePasswordStore(store); err != nil {
		fmt.Printf("Error saving password store: %v\n", err)
		return
	}

	fmt.Printf("Password added successfully (ID: %d)\n", nextID)
}

func updatePassword(id int) {
	masterPassword, err := getMasterPasswordIfNeeded()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error loading password store: %v\n", err)
		return
	}

	// Find the entry to update
	var entryIndex = -1
	var entry *PasswordEntry
	for i := range store.Entries {
		if store.Entries[i].ID == id {
			entryIndex = i
			entry = &store.Entries[i]
			break
		}
	}

	if entryIndex == -1 {
		fmt.Printf("Password with ID %d not found\n", id)
		return
	}

	fmt.Printf("Updating password for: %s (ID: %d)\n", entry.Description, entry.ID)
	fmt.Print("Enter new password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		return
	}

	if len(password) == 0 {
		fmt.Println("Password cannot be empty")
		return
	}

	// Encrypt the new password
	var key []byte
	if isUnlocked() {
		key = masterPassword // masterPassword is already the session key
	} else {
		key = deriveKey(masterPassword, store.Salt)
	}

	encryptedPassword, err := encrypt(string(password), key)
	if err != nil {
		fmt.Printf("Error encrypting password: %v\n", err)
		return
	}

	// Update the entry
	store.Entries[entryIndex].Password = base64.StdEncoding.EncodeToString(encryptedPassword)

	if err := savePasswordStore(store); err != nil {
		fmt.Printf("Error saving password store: %v\n", err)
		return
	}

	fmt.Printf("Password updated successfully for '%s' (ID: %d)\n", entry.Description, entry.ID)
	if isUnlocked() {
		printSecurityWarning()
	}
}

func getPassword(index int) {
	masterPassword, err := getMasterPasswordIfNeeded()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error loading password store: %v\n", err)
		return
	}

	if len(store.Entries) == 0 {
		fmt.Println("No passwords stored")
		return
	}

	var entry *PasswordEntry
	if index == -1 {
		// Get most recent (last) entry
		entry = &store.Entries[len(store.Entries)-1]
	} else {
		// Find entry by ID
		found := false
		for i := range store.Entries {
			if store.Entries[i].ID == index {
				entry = &store.Entries[i]
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Password with ID %d not found\n", index)
			return
		}
	}

	var key []byte
	if isUnlocked() {
		key = masterPassword // masterPassword is already the session key
	} else {
		key = deriveKey(masterPassword, store.Salt)
	}
	encryptedData, err := base64.StdEncoding.DecodeString(entry.Password)
	if err != nil {
		fmt.Printf("Error decoding password data: %v\n", err)
		return
	}
	decryptedPassword, err := decrypt(encryptedData, key)
	if err != nil {
		fmt.Printf("Error decrypting password: %v\n", err)
		return
	}

	err = clipboard.WriteAll(decryptedPassword)
	if err != nil {
		fmt.Printf("Error copying to clipboard: %v\n", err)
		return
	}

	fmt.Printf("Password for '%s' (ID: %d) copied to clipboard\n", entry.Description, entry.ID)
}

func listPasswords() {
	masterPassword, err := getMasterPasswordIfNeeded()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error loading password store: %v\n", err)
		return
	}

	if len(store.Entries) == 0 {
		fmt.Println("No passwords stored")
		return
	}

	fmt.Println("Stored passwords:")
	fmt.Println("ID | Description | Created")
	fmt.Println("---|-------------|--------")

	for _, entry := range store.Entries {
		fmt.Printf("%2d | %-11s | %s\n",
			entry.ID,
			entry.Description,
			entry.CreatedAt.Format("2006-01-02 15:04"))
	}
}

func deletePassword(id int) {
	masterPassword, err := getMasterPasswordIfNeeded()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error loading password store: %v\n", err)
		return
	}

	// Find and remove entry
	found := false
	for i, entry := range store.Entries {
		if entry.ID == id {
			fmt.Printf("Delete password '%s'? (y/N): ", entry.Description)
			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				fmt.Printf("Error reading response: %v\n", err)
				return
			}

			response = strings.TrimSpace(strings.ToLower(response))
			if response != "y" && response != "yes" {
				fmt.Println("Deletion cancelled")
				return
			}

			store.Entries = append(store.Entries[:i], store.Entries[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("Password with ID %d not found\n", id)
		return
	}

	if err := savePasswordStore(store); err != nil {
		fmt.Printf("Error saving password store: %v\n", err)
		return
	}

	fmt.Printf("Password with ID %d deleted successfully\n", id)
}

func unlockStore() {
	if isUnlocked() {
		fmt.Println("Password store is already unlocked")
		printSecurityWarning()
		return
	}

	// Verify master password by trying to load the store
	masterPassword, err := getMasterPassword()
	if err != nil {
		fmt.Printf("Error reading master password: %v\n", err)
		return
	}

	store, err := loadPasswordStore(masterPassword)
	if err != nil {
		fmt.Printf("Error unlocking password store: %v\n", err)
		return
	}

	// Store session - we'll store the derived key for the store's salt
	if len(store.Entries) > 0 {
		// Derive key using the store's salt
		sessionKey := deriveKey(masterPassword, store.Salt)

		if err := ensureDataDir(); err != nil {
			fmt.Printf("Error creating data directory: %v\n", err)
			return
		}

		// Write session key to file
		keyPath := getKeyFilePath()
		if err := os.WriteFile(keyPath, sessionKey, 0600); err != nil {
			fmt.Printf("Error saving session key: %v\n", err)
			return
		}

		// Create lock file
		lockPath := getLockFilePath()
		if err := os.WriteFile(lockPath, []byte("unlocked"), 0600); err != nil {
			fmt.Printf("Error creating lock file: %v\n", err)
			return
		}

		fmt.Println("Password store unlocked successfully")
		printSecurityWarning()
	} else {
		// For empty stores, we still need to create the session
		sessionKey := deriveKey(masterPassword, store.Salt)

		if err := ensureDataDir(); err != nil {
			fmt.Printf("Error creating data directory: %v\n", err)
			return
		}

		keyPath := getKeyFilePath()
		if err := os.WriteFile(keyPath, sessionKey, 0600); err != nil {
			fmt.Printf("Error saving session key: %v\n", err)
			return
		}

		lockPath := getLockFilePath()
		if err := os.WriteFile(lockPath, []byte("unlocked"), 0600); err != nil {
			fmt.Printf("Error creating lock file: %v\n", err)
			return
		}

		fmt.Println("Password store unlocked successfully")
		printSecurityWarning()
	}
}

func lockStore() {
	if !isUnlocked() {
		fmt.Println("Password store is already locked")
		return
	}

	// Remove lock and key files
	lockPath := getLockFilePath()
	keyPath := getKeyFilePath()

	os.Remove(lockPath)
	os.Remove(keyPath)

	fmt.Println("Password store locked successfully")
}

func showStatus() {
	if isUnlocked() {
		fmt.Println("Password store status: UNLOCKED")
		printSecurityWarning()
	} else {
		fmt.Println("Password store status: LOCKED")
	}
}

func changeMasterPassword() {
	// Always require the current master password, even if unlocked
	fmt.Print("Enter current master password: ")
	currentPassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading current master password: %v\n", err)
		return
	}

	// Load the store with the current master password to verify it's correct
	store, err := loadPasswordStoreWithMasterPassword(currentPassword)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	if len(store.Entries) == 0 {
		fmt.Println("No passwords stored. You can change the master password when you add your first password.")
		return
	}

	// Get the new master password
	fmt.Print("Enter new master password: ")
	newPassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading new master password: %v\n", err)
		return
	}

	fmt.Print("Confirm new master password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("Error reading confirmation password: %v\n", err)
		return
	}

	// Verify passwords match
	if string(newPassword) != string(confirmPassword) {
		fmt.Println("Error: Passwords do not match")
		return
	}

	if len(newPassword) == 0 {
		fmt.Println("Error: New password cannot be empty")
		return
	}

	fmt.Printf("Changing master password and re-encrypting %d stored passwords...\n", len(store.Entries))

	// Generate new salt for the new master password
	newSalt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		fmt.Printf("Error generating new salt: %v\n", err)
		return
	}

	// Derive keys
	currentKey := deriveKey(currentPassword, store.Salt)
	newKey := deriveKey(newPassword, newSalt)

	// Re-encrypt all passwords with progress indication
	totalEntries := len(store.Entries)
	for i := range store.Entries {
		if totalEntries > 1 {
			fmt.Printf("Re-encrypting password %d of %d...\n", i+1, totalEntries)
		}
		// Decrypt with old key
		encryptedData, err := base64.StdEncoding.DecodeString(store.Entries[i].Password)
		if err != nil {
			fmt.Printf("Error decoding password data for entry %d: %v\n", store.Entries[i].ID, err)
			return
		}

		plaintext, err := decrypt(encryptedData, currentKey)
		if err != nil {
			fmt.Printf("Error decrypting password for entry %d: %v\n", store.Entries[i].ID, err)
			return
		}

		// Re-encrypt with new key
		newEncryptedData, err := encrypt(plaintext, newKey)
		if err != nil {
			fmt.Printf("Error re-encrypting password for entry %d: %v\n", store.Entries[i].ID, err)
			return
		}

		// Update the entry
		store.Entries[i].Password = base64.StdEncoding.EncodeToString(newEncryptedData)
	}

	// Update the salt
	store.Salt = newSalt

	// Save the updated store
	if err := savePasswordStore(store); err != nil {
		fmt.Printf("Error saving updated password store: %v\n", err)
		return
	}

	// If the store was unlocked, we need to update the session key or lock it
	if isUnlocked() {
		fmt.Println("Store was unlocked. Locking store for security...")
		lockStore()
	}

	fmt.Printf("Master password changed successfully. All %d passwords have been re-encrypted.\n", len(store.Entries))
	fmt.Println("Please use your new master password for future operations.")
}

// loadPasswordStoreWithMasterPassword always uses the actual master password, ignoring unlock state
func loadPasswordStoreWithMasterPassword(masterPassword []byte) (*PasswordStore, error) {
	filePath := getDataFilePath()

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Create new store with random salt
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		return &PasswordStore{
			Entries: []PasswordEntry{},
			Salt:    salt,
		}, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var store PasswordStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	// Always derive key from master password and salt (ignore unlock state)
	key := deriveKey(masterPassword, store.Salt)

	// Verify master password by trying to decrypt the first entry
	if len(store.Entries) > 0 {
		encryptedData, err := base64.StdEncoding.DecodeString(store.Entries[0].Password)
		if err != nil {
			return nil, fmt.Errorf("corrupted password data")
		}
		_, err = decrypt(encryptedData, key)
		if err != nil {
			return nil, fmt.Errorf("invalid master password")
		}
	}

	return &store, nil
}
