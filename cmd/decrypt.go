package cmd

import (
	"fmt"
	"lets-go/lib"
	"log"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt [filename]",
	Short: "Decrypt a file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		useSteghide, _ := cmd.Flags().GetBool("steghide")

		keyString, err := lib.ReadPassphrase()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v\n", err)
		}

		key := lib.GenerateKey(keyString)

		// Decrypt the file
		err = lib.DecryptFile(filename, key)
		if err != nil {
			log.Fatalf("Failed to decrypt file: %v\n", err)
		}
		fmt.Println("File decrypted successfully")
		if useSteghide {
			fmt.Println("Steghide option is selected. (Mock implementation)")
			// Add your Steghide implementation here
		}
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().BoolP("steghide", "s", false, "Use steghide for additional processing")
}
