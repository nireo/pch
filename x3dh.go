package main

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"slices"
)

// PrekeyBundle is what Alice contacts the server to get Bob's public keys.
type PrekeyBundle struct {
	IdentityKey     []byte
	SignedPrekey    []byte
	PrekeySignature []byte
	OneTimePrekey   []byte // optional
}

type X3DHUser struct {
}

// DH performs a Diffie-Hellman operation between a private and public key.
func DH(privateKey *ecdh.PrivateKey, publicKey *ecdh.PublicKey) ([]byte, error) {
	return privateKey.ECDH(publicKey)
}

// KDF returns 32 bytes of output from the HKDF algorithm.
//
//   - hkdf input key material is the input key material = F || KM where KM is an
//     input byte sequence and F is a byte sequence containing 32 0xFF bytes if curve
//     is X25519, and 57 0xFF bytes if curve is X448.
//   - hkdf salt = A zero-filled byte sequence with length equal to the hash output length
//   - hkdf info = An application-specific byte sequence.
func KDF(km []byte, info string) ([]byte, error) {
	// HKDF salt = A zero-filled byte sequence with length equal to the hash output length
	hash := sha256.New
	keyLen := hash().Size()
	salt := make([]byte, keyLen)         // SHA-256 output length is 32 bytes
	f := slices.Repeat([]byte{0xFF}, 32) // since we are only using X25519

	inputKeyMaterial := append(f, km...)
	hkdfKey, err := hkdf.Key(hash, inputKeyMaterial, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("hkdf.Key failed: %s", err)
	}

	return hkdfKey, nil
}

func (own *PrekeyBundle) generateEphemeral(other PrekeyBundle) ([]byte, error) {
	dh1, error := DH(own.IdentityKey, other.SignedPrekey)
	if error != nil {
		return nil, fmt.Errorf("DH(own.IdentityKey, other.SignedPrekey) failed: %s", error)
	}
}
