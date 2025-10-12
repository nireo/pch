package pch

import (
	"bytes"
	"testing"
)

func TestNewRatchetState(t *testing.T) {
	ratchet, err := NewRatchetState()
	if err != nil {
		t.Fatalf("Failed to create ratchet state: %v", err)
	}

	if ratchet.SendingSecretKey == nil {
		t.Error("Sending secret key should not be nil")
	}

	if ratchet.SendingPublicKey == nil {
		t.Error("Sending public key should not be nil")
	}

	if ratchet.SendingCounter != 0 {
		t.Error("Sending counter should be initialized to 0")
	}

	if ratchet.ReceivingCounter != 0 {
		t.Error("Receiving counter should be initialized to 0")
	}
}

func TestKdfRootKey(t *testing.T) {
	key := make([]byte, 32)
	sharedSecret := make([]byte, 32)

	for i := range key {
		key[i] = byte(i)
		sharedSecret[i] = byte(i + 32)
	}

	rootKey, chainKey := kdfRootKey(key, sharedSecret)

	if len(rootKey) != 32 {
		t.Errorf("Expected root key length 32, got %d", len(rootKey))
	}

	if len(chainKey) != 32 {
		t.Errorf("Expected chain key length 32, got %d", len(chainKey))
	}

	if bytes.Equal(rootKey[:], chainKey[:]) {
		t.Error("Root key and chain key should be different")
	}

	rootKey2, chainKey2 := kdfRootKey(key, sharedSecret)
	if !bytes.Equal(rootKey[:], rootKey2[:]) {
		t.Error("kdfRootKey should be deterministic")
	}

	if !bytes.Equal(chainKey[:], chainKey2[:]) {
		t.Error("kdfRootKey should be deterministic")
	}
}

func TestKdfChainKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	chainKey, messageKey := kdfChainKey(key)

	if len(chainKey) != 32 {
		t.Errorf("Expected chain key length 32, got %d", len(chainKey))
	}

	if len(messageKey) != 32 {
		t.Errorf("Expected message key length 32, got %d", len(messageKey))
	}

	if bytes.Equal(chainKey[:], messageKey[:]) {
		t.Error("Chain key and message key should be different")
	}

	chainKey2, messageKey2 := kdfChainKey(key)
	if !bytes.Equal(chainKey[:], chainKey2[:]) {
		t.Error("kdfChainKey should be deterministic")
	}

	if !bytes.Equal(messageKey[:], messageKey2[:]) {
		t.Error("kdfChainKey should be deterministic")
	}
}

func TestRatchetSendReceive(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("Failed to create Alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("Failed to create Bob: %v", err)
	}

	err = bob.GeneratePrekeys(true)
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	_, sharedSecret, err := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)
	if err != nil {
		t.Fatalf("Failed to create initial message: %v", err)
	}

	aliceRatchet, err := NewRatchetState()
	if err != nil {
		t.Fatalf("Failed to create Alice's ratchet: %v", err)
	}

	bobRatchet, err := NewRatchetState()
	if err != nil {
		t.Fatalf("Failed to create Bob's ratchet: %v", err)
	}

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")
	message := "Hello Bob!"

	encrypted, err := aliceRatchet.Send(message, additionalData)
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	if encrypted.Ciphertext == nil {
		t.Error("Ciphertext should not be nil")
	}

	if len(encrypted.Ciphertext) == 0 {
		t.Error("Ciphertext should not be empty")
	}

	decrypted, err := bobRatchet.Receive(encrypted, additionalData)
	if err != nil {
		t.Fatalf("Failed to receive message: %v", err)
	}

	if decrypted != message {
		t.Errorf("Expected '%s', got '%s'", message, decrypted)
	}

	if aliceRatchet.SendingCounter != 1 {
		t.Errorf(
			"Expected Alice's sending counter to be 1, got %d",
			aliceRatchet.SendingCounter,
		)
	}

	if bobRatchet.ReceivingCounter != 1 {
		t.Errorf(
			"Expected Bob's receiving counter to be 1, got %d",
			bobRatchet.ReceivingCounter,
		)
	}
}

func TestRatchetMultipleMessages(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("Failed to create Alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("Failed to create Bob: %v", err)
	}

	err = bob.GeneratePrekeys(true)
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	_, sharedSecret, err := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)
	if err != nil {
		t.Fatalf("Failed to create initial message: %v", err)
	}

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")
	messages := []string{"First", "Second", "Third", "Fourth"}

	for i, msg := range messages {
		encrypted, err := aliceRatchet.Send(msg, additionalData)
		if err != nil {
			t.Fatalf("Failed to send message %d: %v", i, err)
		}

		decrypted, err := bobRatchet.Receive(encrypted, additionalData)
		if err != nil {
			t.Fatalf("Failed to receive message %d: %v", i, err)
		}

		if decrypted != msg {
			t.Errorf("Message %d: expected '%s', got '%s'", i, msg, decrypted)
		}
	}

	if aliceRatchet.SendingCounter != uint64(len(messages)) {
		t.Errorf(
			"Expected Alice's counter to be %d, got %d",
			len(messages),
			aliceRatchet.SendingCounter,
		)
	}

	if bobRatchet.ReceivingCounter != uint64(len(messages)) {
		t.Errorf(
			"Expected Bob's counter to be %d, got %d",
			len(messages),
			bobRatchet.ReceivingCounter,
		)
	}
}

func TestRatchetDecryptionFail(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(true)
	bobBundle, _ := bob.CreatePrekeyBundle()
	_, sharedSecret, _ := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")
	encrypted, _ := aliceRatchet.Send("Secret message", additionalData)

	encrypted.Ciphertext[0] ^= 0xFF

	_, err := bobRatchet.Receive(encrypted, additionalData)
	if err == nil {
		t.Error("Expected decryption to fail with tampered ciphertext")
	}
}

func TestRatchetWrongAdditionalData(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(true)
	bobBundle, _ := bob.CreatePrekeyBundle()
	_, sharedSecret, _ := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	encrypted, _ := aliceRatchet.Send(
		"Secret message",
		[]byte("correct context"),
	)

	_, err := bobRatchet.Receive(encrypted, []byte("wrong context"))
	if err == nil {
		t.Error("Expected decryption to fail with wrong additional data")
	}
}

func TestRatchetEmptyMessage(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(true)
	bobBundle, _ := bob.CreatePrekeyBundle()
	_, sharedSecret, _ := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")

	encrypted, err := aliceRatchet.Send("", additionalData)
	if err != nil {
		t.Fatalf("Failed to send empty message: %v", err)
	}

	decrypted, err := bobRatchet.Receive(encrypted, additionalData)
	if err != nil {
		t.Fatalf("Failed to receive empty message: %v", err)
	}

	if decrypted != "" {
		t.Errorf("Expected empty string, got '%s'", decrypted)
	}
}

func TestRatchetBidirectionalCommunication(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(true)
	bobBundle, _ := bob.CreatePrekeyBundle()
	_, sharedSecret, _ := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeySending = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)
	_, aliceRatchet.ChainKeyReceiving = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")

	msg1, _ := aliceRatchet.Send("Hi Bob", additionalData)
	decrypted1, err := bobRatchet.Receive(msg1, additionalData)
	if err != nil {
		t.Fatalf("Bob failed to receive: %v", err)
	}
	if decrypted1 != "Hi Bob" {
		t.Errorf("Expected 'Hi Bob', got '%s'", decrypted1)
	}

	msg2, _ := bobRatchet.Send("Hi Alice", additionalData)
	decrypted2, err := aliceRatchet.Receive(msg2, additionalData)
	if err != nil {
		t.Fatalf("Alice failed to receive: %v", err)
	}
	if decrypted2 != "Hi Alice" {
		t.Errorf("Expected 'Hi Alice', got '%s'", decrypted2)
	}

	msg3, _ := aliceRatchet.Send("How are you?", additionalData)
	decrypted3, err := bobRatchet.Receive(msg3, additionalData)
	if err != nil {
		t.Fatalf("Bob failed to receive second message: %v", err)
	}
	if decrypted3 != "How are you?" {
		t.Errorf("Expected 'How are you?', got '%s'", decrypted3)
	}
}

func TestRatchetMessageHeader(t *testing.T) {
	ratchet, _ := NewRatchetState()
	additionalData := []byte("context")

	msg, err := ratchet.Send("test", additionalData)
	if err != nil {
		t.Fatalf("Failed to send: %v", err)
	}

	if len(msg.Header.PublicKey) != 32 {
		t.Errorf(
			"Expected public key length 32, got %d",
			len(msg.Header.PublicKey),
		)
	}

	if msg.Header.Counter != 0 {
		t.Errorf(
			"Expected counter 0 for first message, got %d",
			msg.Header.Counter,
		)
	}

	if len(msg.Header.Nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(msg.Header.Nonce))
	}

	if !bytes.Equal(msg.Header.PublicKey[:], ratchet.SendingPublicKey.Bytes()) {
		t.Error("Header public key doesn't match ratchet sending public key")
	}
}

func TestRatchetCounterIncrement(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(true)
	bobBundle, _ := bob.CreatePrekeyBundle()
	_, sharedSecret, _ := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("Initial"),
	)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	copy(aliceRatchet.RootKey[:], sharedSecret)
	copy(bobRatchet.RootKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	bobRatchet.ReceivingPublicKey = aliceRatchet.SendingPublicKey

	var emptySecret [32]byte
	_, aliceRatchet.ChainKeySending = kdfRootKey(
		aliceRatchet.RootKey[:],
		emptySecret[:],
	)
	_, bobRatchet.ChainKeyReceiving = kdfRootKey(
		bobRatchet.RootKey[:],
		emptySecret[:],
	)

	additionalData := []byte("context")

	for i := 0; i < 5; i++ {
		msg, _ := aliceRatchet.Send("test", additionalData)

		if msg.Header.Counter != uint64(i) {
			t.Errorf(
				"Expected counter %d in header, got %d",
				i,
				msg.Header.Counter,
			)
		}

		bobRatchet.Receive(msg, additionalData)
	}

	if aliceRatchet.SendingCounter != 5 {
		t.Errorf(
			"Expected Alice's counter to be 5, got %d",
			aliceRatchet.SendingCounter,
		)
	}

	if bobRatchet.ReceivingCounter != 5 {
		t.Errorf(
			"Expected Bob's counter to be 5, got %d",
			bobRatchet.ReceivingCounter,
		)
	}
}
