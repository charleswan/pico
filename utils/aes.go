package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

// ConnectToServer establishes a TCP connection to the specified server address.
func ConnectToServer(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	return conn, nil
}

// GenerateAESKey generates a 256-bit (32-byte) AES key.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit AES key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	return key, nil
}

// NewAESCipher creates a new AES cipher block from the provided key.
func NewAESCipher(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	return block, nil
}
