package pch

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// RatchetState keeps track of counters and used cryptographic keys.
type RatchetState struct {
	// current keypair for encrypting outgoing messages
	SendingSecretKey *ecdh.PrivateKey
	SendingPublicKey *ecdh.PublicKey

	// the other party's public key
	ReceivingPublicKey *ecdh.PublicKey

	// the master key that gets updated with each ratchet step
	RootKey [32]byte

	// keys that derive individual messages keys for each sent/received message
	ChainKeySending   [32]byte
	ChainKeyReceiving [32]byte

	// tracking for amount of messages
	SendingCounter   uint64
	ReceivingCounter uint64
}

// RatchetMessage contains a ciphertext and the header that is used to decode
// said message.
type RatchetMessage struct {
	Header     RatchetMessageHeader
	Ciphertext []byte
}

// RatchetMessageHeader contains the ,etadata needed to decrypt messages
type RatchetMessageHeader struct {
	PublicKey [32]byte
	Counter   uint64
	Nonce     [12]byte
}

// Conversation represents an ongoing conversation.
type Conversation struct {
	RemoteIdentityKey *ecdh.PublicKey
	SessionID         []byte // unique identifier for this conversation
	Ratchet           *RatchetState
	AdditionalData    []byte
}

// NewRatchetState initializes a ratchet state by generating a new X25519 key
// pair.
func NewRatchetState() (*RatchetState, error) {
	curve := ecdh.X25519()
	secretKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return &RatchetState{
		SendingSecretKey: secretKey,
		SendingPublicKey: secretKey.PublicKey(),
	}, nil
}

// kdfRootKey derives new root and chain keys from the current root key and a
// Diffie-Hellman shared secret. This is called during the "DH ratchet step"
// when public keys are rotated between parties.
//
// The function uses BLAKE2b XOF to produce 64 bytes of output:
//   - First 32 bytes become the new root key (used in future ratchet steps)
//   - Last 32 bytes become the new chain key (used to derive message keys)
//
// This ensures that even if message keys are compromised, past and future
// messages remain secure (forward secrecy and backward secrecy).
func kdfRootKey(key []byte, sharedSecret []byte) ([32]byte, [32]byte) {
	h, _ := blake2b.NewXOF(64, nil)
	h.Write([]byte("DOUBLE_RATCHET_KDF_ROOT_KEY"))
	h.Write(key)
	h.Write(sharedSecret)

	var output [64]byte
	h.Read(output[:])

	var rootKey [32]byte
	var chainKey [32]byte
	copy(rootKey[:], output[0:32])
	copy(chainKey[:], output[32:64])

	return rootKey, chainKey
}

// kdfChainKey derives a new chain key and message key from the current chain
// key. This implements the "symmetric-key ratchet" that evolves with each
// message.
//
// The function uses BLAKE2b XOF to produce 64 bytes of output:
// - First 32 bytes become the next chain key (for the next message in the
// chain)
// - Last 32 bytes become the message key (used to encrypt/decrypt this specific
// message)
//
// By deriving a unique message key for each message and immediately replacing
// the chain key, this ensures perfect forward secrecy: compromising the current
// state doesn't reveal keys for past messages.
func kdfChainKey(key []byte) ([32]byte, [32]byte) {
	h, _ := blake2b.NewXOF(64, nil)
	h.Write([]byte("DOUBLE_RATCHET_KDF_CHAIN_KEY"))
	h.Write(key)

	var output [64]byte
	h.Read(output[:])

	var chainKey [32]byte
	var messageKey [32]byte
	copy(chainKey[:], output[0:32])
	copy(messageKey[:], output[32:64])

	return chainKey, messageKey
}

// Send encrypts and sends a message. Derives a new chain key and message key
// from the current sending key generates a header with a random 12-byte nonce
// and the counter. Encrypts the message using the chacha20poly1305 AEAD with
// the message key and finally increments the sending counter and returns the
// encrypted message.
func (r *RatchetState) Send(
	message string,
	additionalData []byte,
) (*RatchetMessage, error) {
	newChainKeySending, messageKey := kdfChainKey(r.ChainKeySending[:])
	r.ChainKeySending = newChainKeySending

	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	var pubKeyBytes [32]byte
	copy(pubKeyBytes[:], r.SendingPublicKey.Bytes())

	header := RatchetMessageHeader{
		PublicKey: pubKeyBytes,
		Counter:   r.SendingCounter,
		Nonce:     nonce,
	}

	// Encrypt message
	aead, err := chacha20poly1305.New(messageKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce[:], []byte(message), additionalData)
	msg := &RatchetMessage{
		Header:     header,
		Ciphertext: ciphertext,
	}

	r.SendingCounter++

	return msg, nil
}

// Receive extrancts the public key from the message header. If the public key
// is new it performs
// the DH ratchet step:
//   - Derives new root key and receiving chain key
//   - Generates a new sending key pair
//   - Performs another DH ratchet step to derive new sending chain key
//
// Derives the message key from the receiving chain key, increments the counters
// and returns the decrypted message.
func (r *RatchetState) Receive(
	msg *RatchetMessage,
	additionalData []byte,
) (string, error) {
	receivedPubKey, err := ecdh.X25519().NewPublicKey(msg.Header.PublicKey[:])
	if err != nil {
		return "", fmt.Errorf("invalid public key in header: %w", err)
	}

	if r.ReceivingPublicKey == nil ||
		!bytes.Equal(r.ReceivingPublicKey.Bytes(), receivedPubKey.Bytes()) {
		r.ReceivingPublicKey = receivedPubKey

		dhShared, err := r.SendingSecretKey.ECDH(r.ReceivingPublicKey)
		if err != nil {
			return "", fmt.Errorf("DH failed: %w", err)
		}
		r.RootKey, r.ChainKeyReceiving = kdfRootKey(r.RootKey[:], dhShared)

		newSecretKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("failed to generate key: %w", err)
		}
		r.SendingSecretKey = newSecretKey
		r.SendingPublicKey = newSecretKey.PublicKey()

		dhShared, err = r.SendingSecretKey.ECDH(r.ReceivingPublicKey)
		if err != nil {
			return "", fmt.Errorf("DH failed: %w", err)
		}
		r.RootKey, r.ChainKeySending = kdfRootKey(r.RootKey[:], dhShared)
	}

	chainKeyReceiving, messageKey := kdfChainKey(r.ChainKeyReceiving[:])
	r.ChainKeyReceiving = chainKeyReceiving

	aead, err := chacha20poly1305.New(messageKey[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext, err := aead.Open(
		nil,
		msg.Header.Nonce[:],
		msg.Ciphertext,
		additionalData,
	)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	r.ReceivingCounter++
	return string(plaintext), nil
}
