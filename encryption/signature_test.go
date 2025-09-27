package encryption

import (
	"math/big"
	"testing"
)

func TestSignature(t *testing.T) {
	// generate keypair
	keypair := KeyGen(512)

	// test message
	message := big.NewInt(42)

	// sign message
	signature := Sign(message, keypair.Sk)

	// verify signature
	valid := Verify(message, signature, keypair.Pk)
	if !valid {
		t.Errorf("Failed to verify signature")
	}
}

func TestSignatureInvalid(t *testing.T) {
	// generate keypair
	keypair := KeyGen(512)

	// test message
	message := big.NewInt(42)

	// sign message
	signature := Sign(message, keypair.Sk)

	// modify message
	modifiedMessage := big.NewInt(43)

	// verify signature with modified message
	valid := Verify(modifiedMessage, signature, keypair.Pk)
	if valid {
		t.Errorf("Signature should not be valid for modified message")
	}
}
