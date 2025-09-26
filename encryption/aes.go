package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

func EncryptToFile(filename string, data []byte, key []byte) {
	// create AES cipher
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aes.BlockSize)
	io.ReadFull(rand.Reader, nonce) // randomize nonce
	stream := cipher.NewCTR(block, nonce)

	// encrypt using AES in counter mode
	ciphertext := make([]byte, len(data))
	stream.XORKeyStream(ciphertext, data)

	// file creation and operations
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	// write nonce and ciphertext in the file
	_, err = file.Write(nonce)
	if err != nil {
		panic(err)
	}
	_, err = file.Write(ciphertext)
	if err != nil {
		panic(err)
	}
}

func DecryptFromFile(filename string, key []byte) []byte {
	// read file
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	// split nonce and ciphertext
	nonce := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// recreate AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	stream := cipher.NewCTR(block, nonce)

	// decrypt ciphertext
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext
}
