package encryption

import (
	"crypto/rand"
	"math/big"
)

type SecretKey struct {
	n *big.Int
	d *big.Int
}

type PublicKey struct {
	n *big.Int
	e *big.Int
}

type KeyPair struct {
	sk *SecretKey
	pk *PublicKey
}

func NewSecretKey(n *big.Int, d *big.Int) *SecretKey {
	sk := new(SecretKey)
	sk.n = n
	sk.d = d
	return sk
}

func NewPublicKey(n *big.Int, e *big.Int) *PublicKey {
	pk := new(PublicKey)
	pk.n = n
	pk.e = e
	return pk
}

func NewKeyPair(sk *SecretKey, pk *PublicKey) *KeyPair {
	kp := new(KeyPair)
	kp.sk = sk
	kp.pk = pk
	return kp
}

// generate keys
func KeyGen(k int) *KeyPair {
	// variable declaration
	var p *big.Int
	var q *big.Int
	var err error
	var d *big.Int
	e := big.NewInt(3)

	for {
		// get random prime p
		p, err = rand.Prime(rand.Reader, k/2)

		// error management
		if err != nil {
			panic(err)
		}

		// gcd condition
		pm1 := new(big.Int).Sub(p, big.NewInt(1))
		gcd_p := new(big.Int).GCD(nil, nil, e, pm1)
		condition_p := (gcd_p.Cmp(big.NewInt(1)) == 0)

		if !condition_p {
			continue
		}

		// get random prime q
		q, err = rand.Prime(rand.Reader, k/2)

		// error management
		if err != nil {
			panic(err)
		}

		// gcd condition
		qm1 := new(big.Int).Sub(q, big.NewInt(1))
		gcd_q := new(big.Int).GCD(nil, nil, e, qm1)
		condition_q := (gcd_q.Cmp(big.NewInt(1)) == 0)

		if !condition_q {
			continue
		}

		// d condition
		mult := new(big.Int).Mul(pm1, qm1) // (p -1)*(q-1)
		d = new(big.Int).ModInverse(e, mult)
		condition_d := (d != nil)

		// all conditions true -> found fitting p and q
		if condition_d {
			break
		}
	}
	// make and return keypair
	n := new(big.Int).Mul(p, q)
	pk := NewPublicKey(n, e)
	sk := NewSecretKey(n, d)
	keyPair := NewKeyPair(sk, pk)
	return keyPair
}

// encrypts message using a public key and returns the ciphertext
func Encrypt(plaintext *big.Int, pk *PublicKey) *big.Int {
	c := new(big.Int).Exp(plaintext, pk.e, pk.n)
	return c
}

// decrypts ciphertext using a secret key and returns the message
func Decrypt(c *big.Int, sk *SecretKey) *big.Int {
	plaintext := new(big.Int).Exp(c, sk.d, sk.n)
	return plaintext
}
