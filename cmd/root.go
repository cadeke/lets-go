package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "lets-go",
	Short: "A CLI tool for file encryption and decryption",
	Long:  `This CLI tool allows you to encrypt and decrypt files, with an optional Steghide feature.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to execute command: %v\n", err)
		os.Exit(1)
	}
}
