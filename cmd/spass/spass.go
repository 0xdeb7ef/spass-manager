package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ITERATION_COUNT = 70000
	KEY_LENGTH      = 256 / 8
	SALT_BYTES      = 20
)

func Decrypt(data_b64 []byte, password string) ([]byte, error) {
	// Decode base64 encoded data
	data, err := base64.StdEncoding.DecodeString(string(data_b64))
	if err != nil {
		return nil, err
	}

	// Extract salt bytes
	salt := data[:SALT_BYTES]

	// Extract IV
	block_size := aes.BlockSize
	iv := data[SALT_BYTES : SALT_BYTES+block_size]

	// Extract encrypted data
	data_enc := data[SALT_BYTES+block_size:]

	// Generate key using PBKDF2 with HMAC SHA256
	key := pbkdf2.Key([]byte(password), salt, ITERATION_COUNT, KEY_LENGTH, sha256.New)

	// Decrypt data using AES CBC mode
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	data_dec := make([]byte, len(data_enc))
	mode.CryptBlocks(data_dec, data_enc)

	// Remove padding (PKCS5)
	data_dec = removePKCS5Padding(data_dec)

	return data_dec, nil
}

// removePKCS5Padding removes padding from decrypted data
func removePKCS5Padding(data []byte) []byte {
	paddingLen := int(data[len(data)-1])
	return data[:len(data)-paddingLen]
}

// TODO - Implement the Encrypt() function
