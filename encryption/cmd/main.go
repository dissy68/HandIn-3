package main

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"time"

	"encryption"
)

func timeFunc(f func()) time.Duration {
	start := time.Now()
	f()
	return time.Since(start)
}

func main() {
	messageLen := 10 * 1024

	message, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(messageLen*8)))
	if err != nil {
		panic(err)
	}
	println("Testing RSA signatures with", messageLen, "byte message and 2000-bit keys")
	println()

	// Requirement 2
	hash := sha256.New()
	iterations := 1000
	hashDuration := timeFunc(func() {
		for i := 0; i < iterations; i++ {
			hash.Reset()
			hash.Write(message.Bytes())
			hash.Sum(nil)
		}
	})

	avgHashDuration := hashDuration.Nanoseconds() / int64(iterations)
	hashSpeedBitsPerSec := float64(messageLen*8) / (float64(avgHashDuration) / 1e9)

	println("SHA-256 hashing:")
	println("  Average time per hash:", avgHashDuration, "ns for", messageLen, "bytes")
	println("  Hashing speed:", int64(hashSpeedBitsPerSec), "bits/s")
	println()

	// Requirement 3
	hash.Reset()
	hash.Write(message.Bytes())
	hashedMessage := new(big.Int).SetBytes(hash.Sum(nil))

	rsaKeyLen := 2000
	keyPair := encryption.KeyGen(rsaKeyLen)

	signIterations := 10
	hashedMessageSignatureDuration := timeFunc(func() {
		for i := 0; i < signIterations; i++ {
			encryption.Sign(hashedMessage, keyPair.Sk)
		}
	})

	avgSignDuration := hashedMessageSignatureDuration.Nanoseconds() / int64(signIterations)
	hashBits := 256

	println("RSA signing of hash value:")
	println("  Average signing time:", avgSignDuration, "ns for", hashBits, "bit hash")
	println("  Time per signature:", avgSignDuration/1000, "µs")
	println()

	// Requirement 4
	bitsPerRSAOp := 2000
	rsaSpeedBitsPerSec := float64(bitsPerRSAOp) / (float64(avgSignDuration) / 1e9)

	println("Theoretical RSA speed for entire message:")
	println("  Direct RSA speed:", int64(rsaSpeedBitsPerSec), "bits/s")
	println()

	println("Efficiency comparison:")
	println("  SHA-256 hashing speed:   ", int64(hashSpeedBitsPerSec), "bits/s")
	println("  Direct RSA signing speed:", int64(rsaSpeedBitsPerSec), "bits/s")

	efficiency := hashSpeedBitsPerSec / rsaSpeedBitsPerSec
	println("  Hashing is", int64(efficiency), "times faster than direct RSA")
	println()

	if efficiency > 1 {
		println("CONCLUSION: Yes, hashing makes signing much more efficient!")
		println("Hash-then-sign allows processing large messages at hashing speed,")
		println("while only requiring one RSA operation regardless of message size.")
	} else {
		println("CONCLUSION: Direct RSA would be faster (unexpected result)")
	}
}
