package main

import (
	"io"
	"os"
	"testing"
)

func TestReadPassphrase(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Matching passphrases",
			input:       "secret-password\nsecret-password\n",
			expected:    "secret-password",
			expectError: false,
		},
		{
			name:        "Non-matching passphrases",
			input:       "a-simple-password\nanother-simple-password\n",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Backup the original os.Stdin
			originalStdin := os.Stdin
			originalStdout := os.Stdout
			defer func() {
				os.Stdin = originalStdin
				os.Stdout = originalStdout
			}()

			// Set the os.Stdin to the test input
			r, w, _ := os.Pipe()
			_, _ = w.WriteString(tt.input)
			_ = w.Close()
			os.Stdin = r

			// Redirect os.Stdout to a pipe (hiding stdOut)
			stdoutR, stdoutW, _ := os.Pipe()
			os.Stdout = stdoutW
			defer stdoutW.Close()

			// Call the function
			result, err := readPassphrase()

			// Close stdoutW and read from stdoutR to discard the output
			_ = stdoutW.Close()
			_, _ = io.ReadAll(stdoutR)

			// Check for expected error
			if (err != nil) != tt.expectError {
				t.Errorf("expected error: %v, got: %v", tt.expectError, err)
			}

			// Check for expected result
			if result != tt.expected {
				t.Errorf("expected result: %v, got: %v", tt.expected, result)
			}
		})
	}
}
