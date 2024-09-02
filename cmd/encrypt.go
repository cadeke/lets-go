package cmd

import (
	"fmt"
	"lets-go/lib"
	"log"

	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt [filename]",
	Short: "Encrypt a file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		useSteghide, _ := cmd.Flags().GetBool("steghide")

		keyString, err := lib.ReadPassphrase()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v\n", err)
		}

		key := lib.GenerateKey(keyString)

		err = lib.EncryptFile(filename, key)
		if err != nil {
			log.Fatalf("Failed to encrypt file: %v\n", err)
		}
		fmt.Println("File encrypted successfully")
		if useSteghide {
			fmt.Println("Steghide option is selected. (Mock implementation)")
			// Add your Steghide implementation here			}
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().BoolP("steghide", "s", false, "Use steghide for additional processing")
}
