package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"pico/utils"
	"strconv"

	"github.com/spf13/cobra"
)

// runServer starts the server to receive and decrypt files.
func runServer(cmd *cobra.Command, args []string) error {
	// Retrieve command-line flags
	listenAddr, _ := cmd.Flags().GetString("listen")
	privateKeyPath, _ := cmd.Flags().GetString("private-key")
	outputDir, _ := cmd.Flags().GetString("output-dir")

	// Step 1: Load the private key
	privateKey, err := utils.LoadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load private key: %w", err)
	}

	// Step 2: Start listening for incoming connections
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer listener.Close()

	fmt.Println("Server started, waiting for connections...")

	// Step 3: Accept incoming connections and handle them
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn, privateKey, outputDir)
	}
}

// handleConnection handles an incoming connection, decrypts the file, and saves it.
func handleConnection(conn net.Conn, privateKey interface{}, outputDir string) {
	defer conn.Close()

	// Step 1: Read the length of the key exchange JSON
	lengthBytes := make([]byte, 6)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		fmt.Println("Error reading key exchange length:", err)
		return
	}
	length, err := strconv.Atoi(string(lengthBytes))
	if err != nil {
		fmt.Println("Error converting key exchange length to integer:", err)
		return
	}

	// Step 2: Read the key exchange JSON
	keyExchangeJSON := make([]byte, length)
	if _, err := io.ReadFull(conn, keyExchangeJSON); err != nil {
		fmt.Println("Error reading key exchange data:", err)
		return
	}

	// Step 3: Unmarshal the key exchange JSON
	var keyExchange KeyExchange
	if err := json.Unmarshal(keyExchangeJSON, &keyExchange); err != nil {
		fmt.Println("Error unmarshaling key exchange data:", err)
		return
	}

	// Step 4: Decrypt the AES key using RSA
	aesKey, err := utils.DecryptWithRSA(keyExchange.EncryptedKey, keyExchange.Nonce, privateKey)
	if err != nil {
		fmt.Println("Error decrypting AES key:", err)
		return
	}

	// Read the length of the nonce for the file name
	nonceFileNameLengthBytes := make([]byte, 6)
	if _, err := io.ReadFull(conn, nonceFileNameLengthBytes); err != nil {
		fmt.Println("Error reading nonce for file name length:", err)
		return
	}
	nonceFileNameLengthStr := string(nonceFileNameLengthBytes)
	nonceFileNameLength, err := strconv.Atoi(nonceFileNameLengthStr)
	if err != nil {
		fmt.Println("Error converting nonce for file name length to integer:", err)
		return
	}

	// Read the nonce for the file name
	nonceFileName := make([]byte, nonceFileNameLength)
	if _, err := io.ReadFull(conn, nonceFileName); err != nil {
		fmt.Println("Error reading nonce for file name:", err)
		return
	}

	// Read the length of the encrypted file name
	encryptedFileNameLengthBytes := make([]byte, 6)
	if _, err := io.ReadFull(conn, encryptedFileNameLengthBytes); err != nil {
		fmt.Println("Error reading encrypted file name length:", err)
		return
	}
	encryptedFileNameLengthStr := string(encryptedFileNameLengthBytes)
	encryptedFileNameLength, err := strconv.Atoi(encryptedFileNameLengthStr)
	if err != nil {
		fmt.Println("Error converting encrypted file name length to integer:", err)
		return
	}

	// Read the encrypted file name
	encryptedFileName := make([]byte, encryptedFileNameLength)
	if _, err := io.ReadFull(conn, encryptedFileName); err != nil {
		fmt.Println("Error reading encrypted file name:", err)
		return
	}

	// Decrypt the file name
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("Error creating GCM cipher:", err)
		return
	}
	decryptedFileName, err := gcm.Open(nil, nonceFileName, encryptedFileName, nil)
	if err != nil {
		fmt.Println("Error decrypting file name:", err)
		return
	}
	fileName := string(decryptedFileName)

	// Step 7: Read the 16-byte IV for OFB mode
	nonceEnc := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(conn, nonceEnc); err != nil {
		fmt.Println("Error reading nonce:", err)
		return
	}

	// Step 8: Initialize AES decryption in OFB mode
	block, err = aes.NewCipher(aesKey)
	if err != nil {
		fmt.Println("Error creating AES cipher:", err)
		return
	}
	stream := cipher.NewOFB(block, nonceEnc)
	reader := &cipher.StreamReader{S: stream, R: conn}

	// Step 9: Save the decrypted file to the output directory
	outputPath := filepath.Join(outputDir, fileName)
	outputFile, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()

	if _, err := io.Copy(outputFile, reader); err != nil {
		fmt.Println("Error copying decrypted file:", err)
		return
	}

	fmt.Println("File received and decrypted successfully:", outputPath)
}
