package lib

import (
	"crypto/rand"
	"io"
	"os"
	"reflect"
	"testing"
)

// Test for reading passphrases.
// Checks if double verification of passphrases works correctly.
func TestReadPassphrase(t *testing.T) {
	tests := []struct {
		name          string
		firstAttempt  string
		secondAttempt string
		result        string
		expectError   bool
	}{
		{
			name:          "Matching passphrases",
			firstAttempt:  "my-secret-password",
			secondAttempt: "my-secret-password",
			result:        "my-secret-password",
			expectError:   false,
		},
		{
			name:          "Non-matching passphrases",
			firstAttempt:  "my-secret-password-123",
			secondAttempt: "my-secret-password-456",
			result:        "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			result, err := doubleCheck(tt.firstAttempt, tt.secondAttempt)

			// Check for expected error
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}

			// Check for expected result
			if result != tt.result {
				t.Errorf("expected result: %v, got: %v", tt.result, result)
			}
		})
	}
}

// Test for key generation.
// Checks if key generated from an input string works correctly.
func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
	}{
		{
			name:     "Simple passphrase",
			input:    "my-secret-password",
			expected: []byte{169, 201, 12, 71, 194, 49, 175, 179, 25, 80, 22, 156, 203, 137, 149, 19, 55, 235, 6, 137, 211, 22, 96, 227, 44, 52, 131, 91, 183, 1, 140, 12},
		},
		{

			name:     "Complex passphrase",
			input:    "C5{b_FS=Dgdzc@;JUu!3L.#*GAveyW`97B+<",
			expected: []byte{174, 227, 240, 56, 216, 19, 113, 55, 244, 193, 14, 137, 72, 179, 157, 214, 141, 48, 66, 234, 84, 59, 119, 6, 57, 42, 253, 159, 189, 21, 191, 200},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			result := GenerateKey(tt.input)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected result: %v, got: %v", tt.expected, result)
			}
		})
	}
}

// Test for encrypting a file.
// Checks if a file can be read and encrypted correctly.
func TestEncryptFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "encryptFileTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // cleanup

	// Create temp file
	tmpFile, err := os.CreateTemp(tmpDir, "testfile")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Write text to temp file
	plaintext := []byte("This is a test. Testing 123...")
	if _, err := tmpFile.Write(plaintext); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Generate key for encryption
	key := make([]byte, 32) // 32 bytes for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Encrypt file
	encFilename, err := EncryptFile(tmpFile.Name(), key)
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Check name of encrypted file
	if encFilename != tmpFile.Name()+ENC_EXTENSION {
		t.Errorf("Encrypted file name does not match: %v", encFilename)
	}

	// Check if encrypted file exists
	if _, err := os.Stat(encFilename); os.IsNotExist(err) {
		t.Errorf("Encrypted file does not exist: %v", err)
	}

	// Read encrypted file
	encContent, err := os.ReadFile(encFilename)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Check if encrypted file has data
	if len(encContent) == 0 {
		t.Errorf("Encrypted file is empty")
	}
}

// Test for decrypting a file.
// Checks if a file can be first read and encrypted, then decrypted and read again.
func TestDecryptFile(t *testing.T) {

	const TEST_DATA string = "This is a test file. Testing 123..."

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "decryptFileTest")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir) // cleanup

	// Create temp file
	tmpFile, err := os.CreateTemp(tmpDir, "testfile")

	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Write text to temp file
	plaintext := []byte(TEST_DATA)
	if _, err := tmpFile.Write(plaintext); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Generate key
	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Encrypt file
	_, err = EncryptFile(tmpFile.Name(), key)
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Remove original file
	err = os.Remove(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to remove original file: %v", err)
	}

	// Decrypt file
	encFilename := tmpFile.Name() + ENC_EXTENSION
	err = DecryptFile(encFilename, key)

	if err != nil {
		t.Fatalf("Failed to decrypt file: %v", err)
	}

	if _, err := os.Stat(tmpFile.Name()); os.IsNotExist(err) {
		t.Errorf("Decrypted file does not exist: %v", err)
	}

	// Read the decrypted file
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	// Check if data is correct
	data := string(content)
	if data != TEST_DATA {
		t.Errorf("Decrypted file doesn't have the right data. Expected: %v, got: %v", TEST_DATA, data)
	}
}
