package encryption

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"testing"
)

// Test RSA as described in the exercise
func TestRSA(t *testing.T) {
	// generate keypair
	keypair := KeyGen(512)
	// check required length of modulus
	nBits := keypair.Pk.n.BitLen()
	fmt.Println("Modulus bit length:", nBits)
	if nBits != 512 {
		panic("modulus has wrong bit length")
	}

	// check encryption/decryption
	for i := 0; i < 5; i++ {
		// Generate random plaintext smaller than modulus
		data, err := rand.Int(rand.Reader, keypair.Pk.n)
		if err != nil {
			panic(err)
		}
		// enrypt and directly decrypt again
		ciphertext := Encrypt(data, keypair.Pk)
		plaintext := Decrypt(ciphertext, keypair.Sk)

		if plaintext.Cmp(data) != 0 {
			panic(fmt.Sprintf("RSA round-trip failed for message %s", data.String()))
		} else {
			fmt.Println("Test passed for message:", data)
		}
	}

}

func TestAES(t *testing.T) {
	//generate keypair
	keypair := KeyGen(512)

	//serialize the secret key (d and n) as bytes
	d_Bytes := keypair.Sk.d.Bytes()
	n_Bytes := keypair.Sk.n.Bytes()
	serialized := append(n_Bytes, d_Bytes...)

	//derive AES key from some passphrase / fixed key
	passphrase := []byte("thisisa16bytekey")
	key := sha256.Sum256(passphrase) // AES-256

	//encrypt serialized secret key to file
	filename := "rsa_secret.bin"
	EncryptToFile(filename, serialized, key[:])

	//Decrypt from file
	decrypted := DecryptFromFile(filename, key[:])

	//Reconstruct RSA secret key
	recoveredD := new(big.Int).SetBytes(decrypted[len(decrypted)/2:])
	recoveredN := new(big.Int).SetBytes(decrypted[:len(decrypted)/2])
	recoveredSK := NewSecretKey(recoveredN, recoveredD)
	recoveredKP := NewKeyPair(recoveredSK, keypair.Pk)

	//Test RSA encryption/decryption
	msg, _ := rand.Int(rand.Reader, keypair.Pk.n)
	cipher := Encrypt(msg, recoveredKP.Pk)
	plain := Decrypt(cipher, recoveredKP.Sk)

	if plain.Cmp(msg) != 0 {
		panic("Incorrect Decryption")
	}
	fmt.Println("Correct decryption")
	//cleanup
	os.Remove(filename)
}
