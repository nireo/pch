package pch

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// pqxdhVersion has a version for backwards compatibility and proper versioning
type pqxdhVersion uint8

const (
	pqxdhV1 pqxdhVersion = 1
)

// idKEM is a server-addressable id for a KEM key
type idKEM [16]byte

// oneTimeKEMKey contains a single-use KEm key that is supposed to be used only once per pqxdh run
// the user however has a last-resort mlkem key such that the post-quantum security is preserved
type oneTimeKEMKey struct {
	// mlkem keys
	decap *mlkem.DecapsulationKey1024
	encap *mlkem.EncapsulationKey1024

	// metadata
	createdAt int64
	usedAt    *int64
}

// oneTimePreKey are elliptic curve keys that should be used (if available) for each pqxdh run.
// similar to the one time kem keys they should only be used one and then discarded. the receiver
// uses the private key in their key exchange and the iniator uses the public key when initiating
// the key exhange.
type oneTimePreKey struct {
	sk *ecdh.PrivateKey
	pk *ecdh.PublicKey

	// metadata
	createdAt int64
	usedAt    *int64
}

// pqxdhIdentity contains the identity for a given local user. The identity keys should stay the same
type pqxdhIdentity struct {
	// identity signing keys (ed25519)
	signingPub  ed25519.PublicKey
	signingPriv ed25519.PrivateKey

	// identity static DH (X25519)
	pk *ecdh.PublicKey
	sk *ecdh.PrivateKey
}

// pqxdhBundle contains all of the information needed for the iniator to begin key exhange. all of the
// information in this struct is public meaning that in real usage this is populated by a server.
type pqxdhBundle struct {
	signingPub ed25519.PublicKey
	encap      *mlkem.EncapsulationKey1024 // public KEM key (either last-resort or one-time use)
	encapSig   []byte                      // signed by Bob’s identity signing key
	encapID    idKEM                       // id to reference in init

	// classical one-time (optional; server deletes after handing out)
	otpk    *ecdh.PublicKey // optional public X25519 key
	otpkSig []byte

	idpk   *ecdh.PublicKey // identity key
	spkpk  *ecdh.PublicKey // signed prekey
	spkSig []byte          // identity key signature of signed prekey

	version    pqxdhVersion
	bundleHash []byte
}

// pqxdhState represents a user in pqxdh a user can initiate a key exchange or it accept key exchange
// requests to create a shared secret. this struct constains private key which should obviously kept secret.
type pqxdhState struct {
	identity pqxdhIdentity

	// classical signed prekey
	signedPrekeySK *ecdh.PrivateKey
	signedPrekeyPK *ecdh.PublicKey

	// classical one-time prekeys (many; keyed by server-visible id)
	oneTimePrekeys map[uint32]*oneTimePreKey

	// PQ one-time KEM keys (many; keyed by idKEM)
	oneTimeKEMKeys map[idKEM]*oneTimeKEMKey

	// PQ signed prekey (last resort) secret half lives locally
	lastResortKEMkey *mlkem.DecapsulationKey1024
	lastResortKEMid  idKEM

	// optional: metadata
	deviceID  uint32
	version   pqxdhVersion
	createdAt int64
}

type pqxdhInit struct {
	version    pqxdhVersion
	bundleHash []byte // bundle hash such that bob can verify the message content.
	ad         []byte

	identityKey *ecdh.PublicKey
	ephKey      *ecdh.PublicKey
	otpkUsedID  *uint32
	otpkUsedPub *ecdh.PublicKey

	targetEncapID idKEM
	encapCT       []byte

	payload []byte
}

func (ps *pqxdhState) generateOneTimeKEMKeys(n int) error {
	for range n {
		decap, err := mlkem.GenerateKey1024()
		if err != nil {
			return err
		}

		// create a random identifier for the kem key that the server can use
		var id idKEM
		_, err = rand.Read(id[:])
		if err != nil {
			return err
		}

		ps.oneTimeKEMKeys[id] = &oneTimeKEMKey{
			decap:     decap,
			encap:     decap.EncapsulationKey(),
			createdAt: time.Now().Unix(),
			usedAt:    nil,
		}
	}

	return nil
}

func randomUint32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (ps *pqxdhState) generateOneTimePrekeys(n int) error {
	curve := ecdh.X25519()

	for range n {
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate otp: %w", err)
		}

		id, err := randomUint32()
		if err != nil {
			return err
		}

		ps.oneTimePrekeys[id] = &oneTimePreKey{
			sk:        otpPriv,
			pk:        otpPriv.PublicKey(),
			createdAt: time.Now().Unix(),
			usedAt:    nil,
		}
	}

	return nil
}

// ensureHash returns a boolean telling if the value of the bundleHash field matches
// the hashed content.
func (b *pqxdhBundle) isHashValid() (bool, error) {
	got, err := b.hash()
	if err != nil {
		return false, nil
	}

	return bytes.Equal(got, b.bundleHash), nil
}

// hash hashes the content of the bundle
func (b *pqxdhBundle) hash() ([]byte, error) {
	h := sha256.New()

	if b.encap == nil || b.idpk == nil || b.spkpk == nil {
		return nil, errors.New("required fields are nil for hashing")
	}

	h.Write([]byte{byte(b.version)})
	h.Write(b.idpk.Bytes())

	h.Write(b.spkpk.Bytes())
	h.Write(b.spkSig)

	h.Write(b.encap.Bytes())
	h.Write(b.encapID[:])
	h.Write(b.encapSig)

	if b.otpk != nil {
		h.Write(b.otpk.Bytes())
		h.Write(b.otpkSig)
	}

	return h.Sum(nil), nil
}

func pqxdhKDF(km []byte, info string) ([]byte, error) {
	// HKDF salt = A zero-filled byte sequence with length equal to the hash
	// output length
	hash := sha512.New
	keyLen := hash().Size()
	salt := make([]byte, keyLen)
	f := slices.Repeat([]byte{0xFF}, 32)

	inputKeyMaterial := append(f, km...)
	hkdfKey, err := hkdf.Key(hash, inputKeyMaterial, salt, info, keyLen)
	if err != nil {
		return nil, fmt.Errorf("hkdf.Key failed: %s", err)
	}

	return hkdfKey, nil
}

func verifyBundleSignatures() error {
	return nil
}

// keyExchange consumes a bundle and returns derived secret material.
func (ps *pqxdhState) keyExchange(bundle *pqxdhBundle) ([]byte, error) {
	if bundle == nil {
		return nil, errors.New("nil bundle")
	}
	if bundle.idpk == nil || bundle.spkpk == nil || bundle.encap == nil {
		return nil, errors.New("bundle missing required keys")
	}

	ok, err := bundle.isHashValid()
	if err != nil {
		return nil, fmt.Errorf("bundle hash compute failed: %w", err)
	}
	if !ok {
		return nil, errors.New("bundle hash not okay")
	}

	curve := ecdh.X25519()

	// DH1 = IK_A x SPK_B
	dh1, err := ps.identity.sk.ECDH(bundle.spkpk)
	if err != nil {
		return nil, fmt.Errorf("DH1 (IK_AxSPK_B) failed: %w", err)
	}
	ephPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key gen failed: %w", err)
	}

	// DH2 = EK_A x IK_B
	dh2, err := ephPriv.ECDH(bundle.idpk)
	if err != nil {
		return nil, fmt.Errorf("DH2 (EK_AxIK_B) failed: %w", err)
	}

	// DH3 = EK_A x SPK_B
	dh3, err := ephPriv.ECDH(bundle.spkpk)
	if err != nil {
		return nil, fmt.Errorf("DH3 (EK_AxSPK_B) failed: %w", err)
	}

	// Optional DH4 = EK_A x OPK_B
	var dh4 []byte
	if bundle.otpk != nil {
		dh4, err = ephPriv.ECDH(bundle.otpk)
		if err != nil {
			return nil, fmt.Errorf("DH4 (EK_AxOPK_B) failed: %w", err)
		}
	}

	ct, pqSS := bundle.encap.Encapsulate()
	_ = ct

	var km []byte
	km = append(km, dh1...)
	km = append(km, dh2...)
	km = append(km, dh3...)
	if len(dh4) > 0 {
		km = append(km, dh4...)
	}
	km = append(km, pqSS...)

	info := fmt.Sprintf("pqxdh-%d|%x", bundle.version, bundle.bundleHash)

	rootKey, err := pqxdhKDF(km, info)
	if err != nil {
		return nil, err
	}

	return rootKey, nil
}

// buildInit prepares an init message from Alice’s side
func buildInit(version pqxdhVersion, ad []byte) *pqxdhInit {
	return &pqxdhInit{
		version: version,
		ad:      ad,
	}
}
