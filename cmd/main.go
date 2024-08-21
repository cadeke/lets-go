package main

import (
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

	"golang.org/x/term"
)

const ENC_EXTENSION string = ".enc"

// generateKey generates a 32-byte key from a given input string using SHA-256.
//
// The input string is hashed using SHA-256 to produce a fixed-size key.
func generateKey(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

// encryptFile encrypts a file using the provided key.
//
// filename is the path to the file to be encrypted.
// key is the encryption key.
// Returns an error if encryption fails.
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

// decryptFile decrypts a file using the provided key.
//
// filename is the path to the file to be decrypted.
// key is the decryption key.
// Returns an error if decryption fails.
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

// readPassphrase reads and verifies a passphrase from the user.
//
// Returns a string containing the verified passphrase and an error if verification fails.
func readPassphrase() (string, error) {
	fmt.Print("Enter passphrase: ")
	firstAttempt, _ := term.ReadPassword(int(os.Stdin.Fd()))
	firstPw := string(firstAttempt)
	fmt.Println()

	fmt.Print("Verify passphrase: ")
	secondAttempt, _ := term.ReadPassword(int(os.Stdin.Fd()))
	secondPw := string(secondAttempt)
	fmt.Println()

	return doubleCheck(firstPw, secondPw)
}

// doubleCheck checks if two input passphrases match and returns the trimmed passphrase if they do.
//
// p1 and p2 are the two passphrases to be compared.
// Returns the trimmed passphrase as a string and an error if the passphrases do not match.
func doubleCheck(p1 string, p2 string) (string, error) {
	if p1 != p2 {
		return "", errors.New("passphrases don't match")
	} else {
		return strings.TrimSpace(p1), nil
	}
}

// main is the entry point of the program.
//
// It expects two command-line arguments: the action to perform (encrypt or decrypt) and the filename.
// It returns no value but prints the result of the operation to the console.
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
