package pch

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"slices"
)

// PrekeyBundle is what Alice contacts the server to get Bob's public keys.
type PrekeyBundle struct {
	IdentityKey     *ecdh.PublicKey
	SignedPrekey    *ecdh.PublicKey
	PrekeySignature []byte
	OneTimePrekey   *ecdh.PublicKey // optional
}

type X3DHUser struct {
	IdentityPrivateKey  *ecdh.PrivateKey
	IdentityPublicKey   *ecdh.PublicKey
	EphemeralPrivateKey *ecdh.PrivateKey
	EphemeralPublicKey  *ecdh.PublicKey

	SignedPrekeyPrivate  *ecdh.PrivateKey
	SignedPrekeyPublic   *ecdh.PublicKey
	OneTimePrekeyPrivate *ecdh.PrivateKey
	OneTimePrekeyPublic  *ecdh.PublicKey

	SigningKey   ed25519.PrivateKey
	VerifyingKey ed25519.PublicKey

	Username string
}

type InitialMessage struct {
	IdentityKey       *ecdh.PublicKey
	EphemeralKey      *ecdh.PublicKey
	OneTimePrekeyUsed *ecdh.PublicKey // optional

	Payload []byte
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

func NewX3DFUser(username string) (*X3DHUser, error) {
	curve := ecdh.X25519()

	identityPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %s", err)
	}

	pubSign, privSign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %s", err)
	}

	return &X3DHUser{
		IdentityPrivateKey: identityPriv,
		IdentityPublicKey:  identityPriv.PublicKey(),

		SigningKey:   privSign,
		VerifyingKey: pubSign,

		Username: username,
	}, nil
}

func (u *X3DHUser) GenerateEphemeralKey() error {
	curve := ecdh.X25519()

	ephemeralPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %s", err)
	}

	u.EphemeralPrivateKey = ephemeralPriv
	u.EphemeralPublicKey = ephemeralPriv.PublicKey()

	return nil
}

func (u *X3DHUser) CreatePrekeyBundle() (*PrekeyBundle, error) {
	if u.SignedPrekeyPublic == nil {
		return nil, fmt.Errorf("no signed prekey to available")
	}

	signature := ed25519.Sign(u.SigningKey, u.SignedPrekeyPublic.Bytes())
	return &PrekeyBundle{
		IdentityKey:     u.IdentityPublicKey,
		SignedPrekey:    u.SignedPrekeyPublic,
		PrekeySignature: signature,
		OneTimePrekey:   u.OneTimePrekeyPublic, // this can be nill
	}, nil
}

func (u *X3DHUser) GeneratePrekeys(oneTime bool) error {
	curve := ecdh.X25519()

	signedPrekeyPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate signed prekey: %s", err)
	}
	u.SignedPrekeyPrivate = signedPrekeyPriv
	u.SignedPrekeyPublic = signedPrekeyPriv.PublicKey()

	if oneTime {
		oneTimePriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate one-time prekey: %s", err)
		}

		u.OneTimePrekeyPrivate = oneTimePriv
		u.OneTimePrekeyPublic = oneTimePriv.PublicKey()
	}

	return nil
}

func (u *X3DHUser) generateSharedSecret(other PrekeyBundle) ([]byte, error) {
	dh1, err := DH(u.IdentityPrivateKey, other.SignedPrekey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.IdentityKey, other.SignedPrekey) failed: %s", err)
	}

	dh2, err := DH(u.EphemeralPrivateKey, other.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.EphemeralKey, other.IdentityKey) failed: %s", err)
	}

	dh3, err := DH(u.EphemeralPrivateKey, other.SignedPrekey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.EphemeralKey, other.SignedPrekey) failed: %s", err)
	}

	dh1 = append(dh1, dh2...)
	dh1 = append(dh1, dh3...)

	if other.OneTimePrekey != nil {
		dh4, err := DH(u.EphemeralPrivateKey, other.OneTimePrekey)
		if err != nil {
			return nil, fmt.Errorf("DH(own.EphemeralKey, other.OneTimePrekey) failed: %s", err)
		}

		dh1 = append(dh1, dh4...)
	}

	sharedSecret, err := KDF(dh1, "X3DH key agreement")
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %s", err)
	}

	// since we have now calculated the shared secret, the ephemeral private key
	// should be deleted.
	u.EphemeralPrivateKey = nil
	u.EphemeralPublicKey = nil

	return sharedSecret, nil
}

func (u *X3DHUser) additionalInformation(other *ecdh.PublicKey) ([]byte, error) {
	ad := append(u.IdentityPublicKey.Bytes(), other.Bytes()...)
	ad = append(ad, []byte(u.Username)...)

	return ad, nil
}

func (u *X3DHUser) calculateSharedSecretAsReceiver(msg InitialMessage) ([]byte, error) {
	dh1, err := DH(u.SignedPrekeyPrivate, msg.IdentityKey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.SignedPrekey, other.IdentityKey) failed: %s", err)
	}
	dh2, err := DH(u.IdentityPrivateKey, msg.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.IdentityKey, other.EphemeralKey) failed: %s", err)
	}
	dh3, err := DH(u.SignedPrekeyPrivate, msg.EphemeralKey)
	if err != nil {
		return nil, fmt.Errorf("DH(own.SignedPrekey, other.EphemeralKey) failed: %s", err)
	}

	dh1 = append(dh1, dh2...)
	dh1 = append(dh1, dh3...)

	if msg.OneTimePrekeyUsed != nil && u.OneTimePrekeyPrivate != nil {
		if slices.Equal(msg.OneTimePrekeyUsed.Bytes(), u.OneTimePrekeyPublic.Bytes()) {
			dh4, err := DH(u.OneTimePrekeyPrivate, msg.EphemeralKey)
			if err != nil {
				return nil, fmt.Errorf("DH(own.OneTimePrekey, other.EphemeralKey) failed: %s", err)
			}
			dh1 = append(dh1, dh4...)

			u.OneTimePrekeyPrivate = nil
			u.OneTimePrekeyPublic = nil
		}
	}

	sharedSecret, err := KDF(dh1, "X3DH key agreement")
	if err != nil {
		return nil, fmt.Errorf("KDF failed: %s", err)
	}

	return sharedSecret, nil
}

func (u *X3DHUser) CreateInitialMessage(bundle PrekeyBundle, payload []byte) (*InitialMessage, []byte, error) {
	if u.EphemeralPrivateKey == nil {
		if err := u.GenerateEphemeralKey(); err != nil {
			return nil, nil, fmt.Errorf("failed to generate ephemeral key: %s", err)
		}
	}

	ephemeralPubKey := u.EphemeralPublicKey
	sharedSecret, err := u.generateSharedSecret(bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate shared secret: %s", err)
	}

	msg := &InitialMessage{
		IdentityKey:       u.IdentityPublicKey,
		EphemeralKey:      ephemeralPubKey,
		OneTimePrekeyUsed: bundle.OneTimePrekey, // can be nil
		Payload:           payload,
	}

	return msg, sharedSecret, nil
}

func verifyPrekeySignature(bundle PrekeyBundle, verifyingKey ed25519.PublicKey) bool {
	return ed25519.Verify(verifyingKey, bundle.SignedPrekey.Bytes(), bundle.PrekeySignature)
}

func main() {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		panic(err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		panic(err)
	}

	err = bob.GeneratePrekeys(true)
	if err != nil {
		panic(err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		panic(err)
	}

	initialMsg, aliceSecret, err := alice.CreateInitialMessage(*bobBundle, []byte("Hello Bob!"))
	if err != nil {
		panic(err)
	}

	bobSecret, err := bob.calculateSharedSecretAsReceiver(*initialMsg)
	if err != nil {
		panic(err)
	}

	if slices.Equal(aliceSecret, bobSecret) {
		fmt.Println("X3DH key agreement successful!")
		fmt.Printf("Shared secret: %x\n", aliceSecret)
	} else {
		fmt.Println("Key agreement failed - secrets don't match")
	}
}
