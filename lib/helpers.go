package lib

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"strings"

	steg "github.com/auyer/steganography"
	"golang.org/x/term"
)

const ENC_EXTENSION string = ".enc"

// generateKey generates a 32-byte key from a given input string using SHA-256.
//
// The input string is hashed using SHA-256 to produce a fixed-size key.
func GenerateKey(input string) []byte {
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

// encryptFile encrypts a file using the provided key.
//
// filename is the path to the file to be encrypted.
// key is the encryption key.
// Returns an error if encryption fails.
func EncryptFile(filename string, key []byte) error {
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
func DecryptFile(filename string, key []byte) error {
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
func ReadPassphrase() (string, error) {
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

// embed embeds a data file into an image.
func embed(filePath string, imagePath string) error {
	inFile, err := os.Open(imagePath)
	defer inFile.Close()

	if err != nil {
		return err
	}

	reader := bufio.NewReader(inFile)

	img, err := png.Decode(reader)
	if err != nil {
		return err
	}

	w := new(bytes.Buffer)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = steg.Encode(w, img, data)
	if err != nil {
		return err
	}

	outFile, err := os.Create("out_file.png")
	if err != nil {
		return err
	}

	w.WriteTo(outFile)
	outFile.Close()

	fmt.Println("message embedded!")
	return nil
}

// extract extracts the embedded data from an image.
func extract(filePath string) error {
	inFile, _ := os.Open(filePath) // opening file
	defer inFile.Close()

	reader := bufio.NewReader(inFile) // buffer reader
	img, _ := png.Decode(reader)      // decoding to golang's image.Image

	sizeOfMessage := steg.GetMessageSizeFromImage(img) // retrieving message size to decode in the next line

	msg := steg.Decode(sizeOfMessage, img) // decoding the message from the file

	fmt.Println("message extracted!")
	return os.WriteFile("extracted.txt", msg, 0644)
}
