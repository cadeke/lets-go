package cmd

import (
	"fmt"
	"lets-go/lib"
	"log"

	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:     "decrypt [filename]",
	Aliases: []string{"dec", "d"},
	Short:   "Decrypt a file",
	Long:    "Decyrpt a file that was previously encrypted with the lets-go tool.",
	Example: "decrypt file-to-encrypt.txt",
	Run: func(cmd *cobra.Command, args []string) {
		filename := args[0]
		useSteghide, _ := cmd.Flags().GetBool("steghide")
		if useSteghide {
			fmt.Println("Steghide option is selected. (Mock implementation)")
		}
		keyString, err := lib.ReadPassphrase()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v\n", err)
		}
		key := lib.GenerateKey(keyString)
		err = lib.DecryptFile(filename, key)
		if err != nil {
			log.Fatalf("Failed to decrypt file: %v\n", err)
		}
		fmt.Println("File decrypted successfully")
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().BoolP("steghide", "s", false, "Use steghide for additional processing")
}
