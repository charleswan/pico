package cmd

import (
	"github.com/spf13/cobra"
)

// ClientCmd is the command for sending a file over TCP with encryption.
var ClientCmd = &cobra.Command{
	Use:   "client",
	Short: "Send a file over TCP with encryption",
	RunE:  runClient,
}

// ServerCmd is the command for receiving a file over TCP and decrypting it.
var ServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Receive a file over TCP and decrypt it",
	RunE:  runServer,
}

// GenerateKeysCmd is the command for generating RSA public and private keys.
var GenerateKeysCmd = &cobra.Command{
	Use:   "generate-keys",
	Short: "Generate RSA public and private keys",
	RunE:  generateKeys,
}

// init sets up the command-line flags and marks required flags.
func init() {
	// Client command flags
	ClientCmd.Flags().StringP("file", "f", "", "File to send (required)")
	ClientCmd.Flags().StringP("server", "s", "", "Server IP:Port (required)")
	ClientCmd.Flags().StringP("public-key", "p", "", "Path to public key (required)")
	ClientCmd.MarkFlagRequired("file")
	ClientCmd.MarkFlagRequired("server")
	ClientCmd.MarkFlagRequired("public-key")

	// Server command flags
	ServerCmd.Flags().StringP("listen", "l", "", "Listen address (IP:Port) (required)")
	ServerCmd.Flags().StringP("private-key", "k", "", "Path to private key (required)")
	ServerCmd.Flags().StringP("output-dir", "o", ".", "Directory to save received files")
	ServerCmd.MarkFlagRequired("listen")
	ServerCmd.MarkFlagRequired("private-key")

	// GenerateKeys command flags
	GenerateKeysCmd.Flags().StringP("public-key", "p", "public.pem", "Path to save public key")
	GenerateKeysCmd.Flags().StringP("private-key", "k", "private.pem", "Path to save private key")
}
