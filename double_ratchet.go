package pch

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type RatchetState struct {
	SendingSecretKey   *ecdh.PrivateKey
	SendingPublicKey   *ecdh.PublicKey
	ReceivingPublicKey *ecdh.PublicKey

	RootKey           [32]byte
	ChainKeySending   [32]byte
	ChainKeyReceiving [32]byte

	SendingCounter   uint64
	ReceivingCounter uint64
}

type RatchetMessage struct {
	Header     RatchetMessageHeader
	Ciphertext []byte
}

type RatchetMessageHeader struct {
	PublicKey [32]byte
	Counter   uint64
	Nonce     [12]byte
}

type Conversation struct {
	RemoteIdentityKey *ecdh.PublicKey
	SessionID         []byte // unique identifier for this conversation
	Ratchet           *RatchetState
	AdditionalData    []byte
}

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

func (r *RatchetState) Send(message string, additionalData []byte) (*RatchetMessage, error) {
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

func (r *RatchetState) Receive(msg *RatchetMessage, additionalData []byte) (string, error) {
	receivedPubKey, err := ecdh.X25519().NewPublicKey(msg.Header.PublicKey[:])
	if err != nil {
		return "", fmt.Errorf("invalid public key in header: %w", err)
	}

	if r.ReceivingPublicKey == nil || !bytes.Equal(r.ReceivingPublicKey.Bytes(), receivedPubKey.Bytes()) {
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

	plaintext, err := aead.Open(nil, msg.Header.Nonce[:], msg.Ciphertext, additionalData)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	r.ReceivingCounter++
	return string(plaintext), nil
}
