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
	dataFile   = "passwords.dat"
	keySize    = 32     // AES-256
	nonceSize  = 12     // GCM nonce size
	iterations = 100000 // PBKDF2 iterations
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

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
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("CPW - Clipboard Password Manager")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  cpw add <description>     - Add a new password")
	fmt.Println("  cpw get [index]          - Get password (most recent if no index)")
	fmt.Println("  cpw list                 - List all passwords")
	fmt.Println("  cpw delete <index>       - Delete a password")
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

	// Verify master password by trying to decrypt the first entry
	if len(store.Entries) > 0 {
		key := deriveKey(masterPassword, store.Salt)
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
	masterPassword, err := getMasterPassword()
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

	key := deriveKey(masterPassword, store.Salt)
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

func getPassword(index int) {
	masterPassword, err := getMasterPassword()
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

	key := deriveKey(masterPassword, store.Salt)
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
	masterPassword, err := getMasterPassword()
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
	masterPassword, err := getMasterPassword()
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
