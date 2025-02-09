package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// generateKeys generates RSA public and private keys and saves them to the specified paths.
func generateKeys(cmd *cobra.Command, args []string) error {
	// Retrieve command-line flags
	publicKeyPath, _ := cmd.Flags().GetString("public-key")
	privateKeyPath, _ := cmd.Flags().GetString("private-key")

	// Step 1: Generate a new RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048-bit key
	if err != nil {
		return fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	// Step 2: Encode the private key to PEM format
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Step 3: Save the private key to the specified file
	privateKeyFile, err := os.Create(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer privateKeyFile.Close()

	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key to PEM: %w", err)
	}

	// Step 4: Extract the public key from the private key
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Step 5: Encode the public key to PEM format
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	// Step 6: Save the public key to the specified file
	publicKeyFile, err := os.Create(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer publicKeyFile.Close()

	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to encode public key to PEM: %w", err)
	}

	fmt.Println("Keys generated successfully.")
	return nil
}
