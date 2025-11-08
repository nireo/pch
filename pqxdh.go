package pch

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
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
	encap    *mlkem.EncapsulationKey1024 // public KEM key (either last-resort or one-time use)
	encapSig []byte                      // signed by Bob’s identity signing key
	encapID  idKEM                       // id to reference in init

	// classical one-time (optional; server deletes after handing out)
	otpk    *ecdh.PublicKey // optional public X25519 key
	otpkSig []byte

	idpk   *ecdh.PublicKey // identity key
	spkpk  *ecdh.PublicKey // signed prekey
	spkSig []byte          // identity key signature of signed prekey

	version pqxdhVersion
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

// keyExchange consumes a bundle and returns derived secret material.
func (ps *pqxdhState) keyExchange(bundle *pqxdhBundle) ([]byte, error) {
	return nil, nil
}

// buildInit prepares an init message from Alice’s side
func buildInit(version pqxdhVersion, ad []byte) *pqxdhInit {
	return &pqxdhInit{
		version: version,
		ad:      ad,
	}
}
