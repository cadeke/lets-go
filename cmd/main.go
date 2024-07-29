package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const ENC_EXTENSION string = ".enc"

// Generate 32-byte key from a string using SHA-256
func generateKey(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

// Encrypt file using AES-GCM
func encryptFile(filename string, key []byte) error {
	plaintext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return os.WriteFile(filename+ENC_EXTENSION, ciphertext, 0644)
}

// Decrypt file using AES-GCM
func decryptFile(filename string, key []byte) error {
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return os.WriteFile(strings.TrimSuffix(filename, ENC_EXTENSION), plaintext, 0644)
}

// Read passphrase from user, using double verification
func readPassphrase() (string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter passphrase: ")
	firstAttempt, _ := reader.ReadString('\n')

	fmt.Print("Verify passphrase: ")
	secondAttempt, _ := reader.ReadString('\n')

	if firstAttempt != secondAttempt {
		return "", errors.New("passphrases don't match")
	}

	return strings.TrimSpace(firstAttempt), nil
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: lets-go <encrypt|decrypt> <filename>")
		return
	}

	action := os.Args[1]
	filename := os.Args[2]

	keyString, err := readPassphrase()
	if err != nil {
		log.Fatal(err)
	}

	key := generateKey(keyString)

	switch action {
	case "encrypt", "enc":
		err := encryptFile(filename, key)
		if err != nil {
			fmt.Printf("Failed to encrypt file: %v\n", err)
		} else {
			fmt.Println("File encrypted successfully")
		}
	case "decrypt", "dec":
		err := decryptFile(filename, key)
		if err != nil {
			fmt.Printf("Failed to decrypt file: %v\n", err)
		} else {
			fmt.Println("File decrypted successfully")
		}
	default:
		fmt.Println("Unknown action:", action)
	}
}
