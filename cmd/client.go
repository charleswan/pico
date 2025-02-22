package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"pico/utils"

	"github.com/spf13/cobra"
)

// KeyExchange represents the structure for key exchange information.
// It contains the encrypted AES key and the nonce used during encryption.
type KeyExchange struct {
	EncryptedKey []byte `json:"encryptedKey"` // Encrypted AES key
	Nonce        []byte `json:"nonce"`        // Nonce used in encryption
}

// runClient is the main function for the client command.
// It handles file sending to the server after performing key exchange.
func runClient(cmd *cobra.Command, args []string) error {
	// Retrieve command-line flags
	filePath, _ := cmd.Flags().GetString("file")
	serverAddr, _ := cmd.Flags().GetString("server")
	publicKeyPath, _ := cmd.Flags().GetString("public-key")

	// Step 1: Load the public key from the specified path
	publicKey, err := utils.LoadPublicKey(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load public key: %w", err)
	}

	// Step 2: Open the file to be sent
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Step 3: Connect to the server
	conn, err := utils.ConnectToServer(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Step 4: Generate a new AES key for file encryption
	aesKey := make([]byte, 32) // 256-bit AES key
	if _, err := rand.Read(aesKey); err != nil {
		return fmt.Errorf("failed to generate AES key: %w", err)
	}

	// Step 5: Encrypt the AES key using RSA with the public key
	encryptedKey, nonce, err := utils.EncryptWithRSA(aesKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt AES key with RSA: %w", err)
	}

	// Step 6: Prepare the key exchange information
	keyExchange := KeyExchange{
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
	}
	keyExchangeJSON, err := json.Marshal(keyExchange)
	if err != nil {
		return fmt.Errorf("failed to marshal key exchange data: %w", err)
	}

	// Step 7: Send the length of the key exchange JSON
	if err := sendDataLength(conn, len(keyExchangeJSON)); err != nil {
		return fmt.Errorf("failed to send key exchange length: %w", err)
	}

	// Step 8: Send the key exchange JSON
	if _, err := conn.Write(keyExchangeJSON); err != nil {
		return fmt.Errorf("failed to send key exchange data: %w", err)
	}

	// Step 9: Send the file name
	fileName := filepath.Base(filePath)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceFileName := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonceFileName); err != nil {
		return err
	}
	encryptedFileName := gcm.Seal(nil, nonceFileName, []byte(fileName), nil)

	// Send the length of the nonce for the file name
	nonceFileNameLength := len(nonceFileName)
	if _, err := conn.Write([]byte(fmt.Sprintf("%06d", nonceFileNameLength))); err != nil {
		return err
	}
	// Send the nonce for the file name
	if _, err := conn.Write(nonceFileName); err != nil {
		return err
	}

	// Send the length of the encrypted file name
	encryptedFileNameLength := len(encryptedFileName)
	if _, err := conn.Write([]byte(fmt.Sprintf("%06d", encryptedFileNameLength))); err != nil {
		return err
	}
	// Send the encrypted file name
	if _, err := conn.Write(encryptedFileName); err != nil {
		return err
	}

	// Step 10: Initialize AES encryption in OFB mode
	block, err = aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Generate a 16-byte IV for OFB mode
	nonceEnc := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonceEnc); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Send the IV to the server
	if _, err := conn.Write(nonceEnc); err != nil {
		return fmt.Errorf("failed to send IV: %w", err)
	}

	// Step 11: Encrypt and send the file content
	stream := cipher.NewOFB(block, nonceEnc)
	writer := &cipher.StreamWriter{S: stream, W: conn}

	if _, err := io.Copy(writer, file); err != nil {
		return fmt.Errorf("failed to send file content: %w", err)
	}

	fmt.Println("File sent successfully.")
	return nil
}

// sendDataLength sends the length of the data to the server in a fixed 6-byte format.
func sendDataLength(conn io.Writer, length int) error {
	lengthStr := fmt.Sprintf("%06d", length) // Pad the length to 6 digits
	if _, err := conn.Write([]byte(lengthStr)); err != nil {
		return fmt.Errorf("failed to send data length: %w", err)
	}
	return nil
}
