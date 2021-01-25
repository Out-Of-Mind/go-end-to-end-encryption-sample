package main

import (
		"golang.org/x/crypto/curve25519"
		"encoding/hex"
		"math/rand"
		"crypto/aes"
		"crypto/cipher"
		cr "crypto/rand"
		"fmt"
		"time"
		"io"
)

// Person structure
type Person struct {
		pubKey, privKey [32]byte
		key [32]byte
}

// AES encryptor structure
type AES struct {
		pass [32]byte
		cryptor cipher.Block
		nonce []byte
		gcm cipher.AEAD
}

// new Person
func New(pubKey, privKey [32]byte) *Person {
		return &Person{
				pubKey: pubKey,
				privKey: privKey,
		}
}

// new AES structure
func NewAES(pass [32]byte) *AES {
		pass_slice := pass[:]
		cryptor, _ := aes.NewCipher(pass_slice)
		gcm, err := cipher.NewGCM(cryptor)
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(cr.Reader, nonce); err != nil {
				fmt.Println(err)
		}
		return &AES{
				pass: pass,
				cryptor: cryptor,
				nonce: nonce,
				gcm: gcm,
		}
}

// AES function encrypt
func (a *AES) encrypt(text []byte) []byte {
		encr := a.gcm.Seal(a.nonce, a.nonce, text, nil)
		return encr
}

// AES function decrypt
func (a *AES) decrypt(ciphertext []byte) []byte {
		nonceSize := a.gcm.NonceSize()
		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
		plaintext, _ := a.gcm.Open(nil, nonce, ciphertext, nil)
		return plaintext
}

// generating public and private keys (Diffie–Hellman key exchange based on curve25519)
func gen() ([32]byte, [32]byte) {
		rand.Seed(time.Now().UnixNano())

		var privateKey  [32]byte
		for i := range privateKey[:] {
				privateKey[i] = byte(rand.Intn(256))
		}

		var publicKey [32]byte
		curve25519.ScalarBaseMult(&publicKey, &privateKey)

		return publicKey, privateKey
}

// generating out key based on exchanged public key and own private key
func gen_out(pub, priv [32]byte) [32]byte {
		var out [32]byte
		curve25519.ScalarMult(&out, &priv, &pub)
		return out
}

func main() {
		fmt.Println("Starting of example...")
		// first pair of public and private keys
		pu1, pr1 := gen()
		// generating Bob with first pair of public and private keys
		Bob := New(pu1, pr1)
		// second pair of public and private keys
		pu2, pr2 := gen()
		// generating Alisa with second pair of public and private keys
		Alisa := New(pu2, pr2)
		fmt.Println("before exchanging of keys")
		// printing Bob's pair of keys
		fmt.Println("Bob's public and private keys: \n\tpublic: "+hex.EncodeToString(Bob.pubKey[:])+"\n\tprivate: "+hex.EncodeToString(Bob.privKey[:]))
		// printing Alisa's pair of keys
		fmt.Println("Alisa's public and private keys: \n\tpublic: "+hex.EncodeToString(Alisa.pubKey[:])+"\n\tprivate: "+hex.EncodeToString(Alisa.privKey[:]))
		// public keys exchanging
		Alisa.pubKey, Bob.pubKey = Bob.pubKey, Alisa.pubKey
		fmt.Println("after exchanging of keys")
		// printing Bob's pair of keys after exchanging
		fmt.Println("Bob's public and private keys: \n\tpublic: "+hex.EncodeToString(Bob.pubKey[:])+"\n\tprivate: "+hex.EncodeToString(Bob.privKey[:]))
		// printing Alisa's pair of keys after exchanging
		fmt.Println("Alisa's public and private keys: \n\tpublic: "+hex.EncodeToString(Alisa.pubKey[:])+"\n\tprivate: "+hex.EncodeToString(Alisa.privKey[:]))
		// generate Bob's out key to encrypt/decrypt messages
		Bob.key = gen_out(Bob.pubKey, Bob.privKey)
		// generating Alisa's out key to encrypt/decrypr messages
		Alisa.key = gen_out(Alisa.pubKey, Alisa.privKey)
		// printing generated out keys
		fmt.Println("Generated out keys:\n\tBob's: ( "+hex.EncodeToString(Bob.key[:])+" )\n\tAlisa's: ("+hex.EncodeToString(Alisa.key[:])+" )")
		// new AES instance with Alisa's out key
		a := NewAES(Alisa.key)
		// new AES instance with Bob's out key
		a1 := NewAES(Bob.key)
		// encrypting message with Alisa's out key
		encrypted_message := a.encrypt([]byte("Hi, I'm Alisa"))
		// print encrypted message
		fmt.Println("encrypted message ( "+string(encrypted_message)+" )")
		// decryptingm message
		decrypted_message := a1.decrypt(encrypted_message)
		// print decrypted message
		fmt.Println("decrypted message ( "+string(decrypted_message)+" )")
}
