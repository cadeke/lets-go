package cmd

import (
	"fmt"
	"lets-go/lib"
	"log"

	"github.com/spf13/cobra"
)

var stegFile string

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt [filename]",
	Short: "Encrypt a file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		stegFile, _ := cmd.Flags().GetString("steghide")

		keyString, err := lib.ReadPassphrase()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v\n", err)
		}

		key := lib.GenerateKey(keyString)

		file, err := lib.EncryptFile(filename, key)
		if err != nil {
			log.Fatalf("Failed to encrypt file: %v\n", err)
		}

		fmt.Println("File encrypted successfully")

		if stegFile != "" {
			fmt.Println("Steghide option is selected. (Mock implementation)")
			err = lib.Embed(file, stegFile)
			if err != nil {
				log.Fatalf("Failed to embed file: %v\n", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringVarP(&stegFile, "steghide", "s", "", "Use steghide for additional processing")
}
