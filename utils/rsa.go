package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadPublicKey loads an RSA public key from the specified file path.
func LoadPublicKey(path string) (interface{}, error) {
	// Read the public key file
	keyFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyFile)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pub, nil
}

// LoadPrivateKey loads an RSA private key from the specified file path.
func LoadPrivateKey(path string) (interface{}, error) {
	// Read the private key file
	keyFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(keyFile)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse the private key
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return priv, nil
}

// EncryptWithRSA encrypts the given data using RSA-OAEP with SHA-256.
// It returns the encrypted data and the nonce used during encryption.
func EncryptWithRSA(data []byte, publicKey interface{}) ([]byte, []byte, error) {
	// Generate a 16-byte nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data using RSA-OAEP
	encryptedData, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey.(*rsa.PublicKey),
		data,
		nonce,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt data with RSA: %w", err)
	}

	return encryptedData, nonce, nil
}

// DecryptWithRSA decrypts the given data using RSA-OAEP with SHA-256.
// It requires the nonce used during encryption.
func DecryptWithRSA(data []byte, nonce []byte, privateKey interface{}) ([]byte, error) {
	// Decrypt the data using RSA-OAEP
	decryptedData, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey.(*rsa.PrivateKey),
		data,
		nonce,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with RSA: %w", err)
	}

	return decryptedData, nil
}
