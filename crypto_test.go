package pch

import (
	"bytes"
	"testing"
)

func TestX3DHWithDoubleRatchet(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	if err := bob.GeneratePrekeys(true); err != nil {
		t.Fatalf("bob failed to generate prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("bob failed to create prekey bundle: %v", err)
	}

	if !verifyPrekeySignature(*bobBundle, bob.VerifyingKey) {
		t.Fatal("failed to verify bob's prekey signature")
	}

	initialMsg, aliceSharedSecret, err := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("initial payload"),
	)
	if err != nil {
		t.Fatalf("alice failed to create initial message: %v", err)
	}

	bobSharedSecret, err := bob.calculateSharedSecretAsReceiver(initialMsg)
	if err != nil {
		t.Fatalf("bob failed to calculate shared secret: %v", err)
	}

	if !bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		t.Fatal("shared secrets don't match")
	}

	aliceRatchet, err := NewRatchetState()
	if err != nil {
		t.Fatalf("failed to create alice's ratchet: %v", err)
	}

	bobRatchet, err := NewRatchetState()
	if err != nil {
		t.Fatalf("failed to create bob's ratchet: %v", err)
	}

	var sharedKey [32]byte
	copy(sharedKey[:], aliceSharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	dhShared, err := aliceRatchet.SendingSecretKey.ECDH(aliceRatchet.ReceivingPublicKey)
	if err != nil {
		t.Fatalf("alice's initial DH failed: %v", err)
	}
	aliceRatchet.RootKey, aliceRatchet.ChainKeySending = kdfRootKey(sharedKey[:], dhShared)

	bobRatchet.RootKey = sharedKey
	additionalData := append(alice.IdentityPublicKey.Bytes(), bob.IdentityPublicKey.Bytes()...)

	t.Run("AliceToBob", func(t *testing.T) {
		msg, err := aliceRatchet.Send("Hello", additionalData)
		if err != nil {
			t.Fatalf("alice failed to send: %v", err)
		}

		plaintext, err := bobRatchet.Receive(msg, additionalData)
		if err != nil {
			t.Fatalf("bob failed to receive: %v", err)
		}

		if plaintext != "Hello" {
			t.Errorf("expected 'Hello', got '%s'", plaintext)
		}
	})

	t.Run("BobToAlice", func(t *testing.T) {
		msg, err := bobRatchet.Send("World!", additionalData)
		if err != nil {
			t.Fatalf("bob failed to send: %v", err)
		}

		plaintext, err := aliceRatchet.Receive(msg, additionalData)
		if err != nil {
			t.Fatalf("alice failed to receive: %v", err)
		}

		if plaintext != "World!" {
			t.Errorf("expected 'World!', got '%s'", plaintext)
		}
	})

	t.Run("MultipleMessagesFromAlice", func(t *testing.T) {
		msg1, err := aliceRatchet.Send("I'm", additionalData)
		if err != nil {
			t.Fatalf("alice failed to send message 1: %v", err)
		}

		msg2, err := aliceRatchet.Send("Alice", additionalData)
		if err != nil {
			t.Fatalf("alice failed to send message 2: %v", err)
		}

		plaintext1, err := bobRatchet.Receive(msg1, additionalData)
		if err != nil {
			t.Fatalf("bob failed to receive message 1: %v", err)
		}

		plaintext2, err := bobRatchet.Receive(msg2, additionalData)
		if err != nil {
			t.Fatalf("bob failed to receive message 2: %v", err)
		}

		if plaintext1 != "I'm" {
			t.Errorf("expected 'I'm', got '%s'", plaintext1)
		}
		if plaintext2 != "Alice" {
			t.Errorf("expected 'Alice', got '%s'", plaintext2)
		}
	})

	t.Run("BobResponds", func(t *testing.T) {
		msg, err := bobRatchet.Send("I'm Bob", additionalData)
		if err != nil {
			t.Fatalf("bob failed to send: %v", err)
		}

		plaintext, err := aliceRatchet.Receive(msg, additionalData)
		if err != nil {
			t.Fatalf("alice failed to receive: %v", err)
		}

		if plaintext != "I'm Bob" {
			t.Errorf("expected 'I'm Bob', got '%s'", plaintext)
		}
	})
}

func TestX3DHWithoutOneTimePrekey(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	if err := bob.GeneratePrekeys(false); err != nil {
		t.Fatalf("bob failed to generate prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("bob failed to create prekey bundle: %v", err)
	}

	if bobBundle.OneTimePrekey != nil {
		t.Fatal("expected nil one-time prekey")
	}

	initialMsg, aliceSharedSecret, err := alice.CreateInitialMessage(
		*bobBundle,
		[]byte("test"),
	)
	if err != nil {
		t.Fatalf("alice failed to create initial message: %v", err)
	}

	bobSharedSecret, err := bob.calculateSharedSecretAsReceiver(initialMsg)
	if err != nil {
		t.Fatalf("bob failed to calculate shared secret: %v", err)
	}

	if !bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		t.Fatal("shared secrets don't match without one-time prekey")
	}
}

func TestRatchetCounters(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatal(err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatal(err)
	}

	if err := bob.GeneratePrekeys(true); err != nil {
		t.Fatal(err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatal(err)
	}

	initialMsg, aliceSharedSecret, err := alice.CreateInitialMessage(*bobBundle, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = bob.calculateSharedSecretAsReceiver(initialMsg)
	if err != nil {
		t.Fatal(err)
	}

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	var sharedKey [32]byte
	copy(sharedKey[:], aliceSharedSecret)

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	dhShared, _ := aliceRatchet.SendingSecretKey.ECDH(aliceRatchet.ReceivingPublicKey)
	aliceRatchet.RootKey, aliceRatchet.ChainKeySending = kdfRootKey(sharedKey[:], dhShared)
	bobRatchet.RootKey = sharedKey

	additionalData := []byte("test")

	for i := 0; i < 3; i++ {
		if aliceRatchet.SendingCounter != uint64(i) {
			t.Errorf("expected alice sending counter %d, got %d", i, aliceRatchet.SendingCounter)
		}

		msg, err := aliceRatchet.Send("test", additionalData)
		if err != nil {
			t.Fatal(err)
		}

		if bobRatchet.ReceivingCounter != uint64(i) {
			t.Errorf("expected bob receiving counter %d, got %d", i, bobRatchet.ReceivingCounter)
		}

		_, err = bobRatchet.Receive(msg, additionalData)
		if err != nil {
			t.Fatal(err)
		}
	}

	if aliceRatchet.SendingCounter != 3 {
		t.Errorf("expected alice final counter 3, got %d", aliceRatchet.SendingCounter)
	}

	if bobRatchet.ReceivingCounter != 3 {
		t.Errorf("expected bob final counter 3, got %d", bobRatchet.ReceivingCounter)
	}
}

func TestRatchetKeyRotation(t *testing.T) {
	alice, _ := NewX3DFUser("alice")
	bob, _ := NewX3DFUser("bob")

	bob.GeneratePrekeys(false)
	bobBundle, _ := bob.CreatePrekeyBundle()
	initialMsg, aliceSharedSecret, _ := alice.CreateInitialMessage(*bobBundle, nil)
	bob.calculateSharedSecretAsReceiver(initialMsg)

	aliceRatchet, _ := NewRatchetState()
	bobRatchet, _ := NewRatchetState()

	var sharedKey [32]byte
	copy(sharedKey[:], aliceSharedSecret[:])

	aliceRatchet.ReceivingPublicKey = bobRatchet.SendingPublicKey
	dhShared, _ := aliceRatchet.SendingSecretKey.ECDH(aliceRatchet.ReceivingPublicKey)
	aliceRatchet.RootKey, aliceRatchet.ChainKeySending = kdfRootKey(sharedKey[:], dhShared)
	bobRatchet.RootKey = sharedKey

	additionalData := []byte("test")

	msg1, _ := aliceRatchet.Send("first", additionalData)
	oldAlicePublicKey := aliceRatchet.SendingPublicKey

	_, err := bobRatchet.Receive(msg1, additionalData)
	if err != nil {
		t.Fatal(err)
	}

	msg2, _ := bobRatchet.Send("second", additionalData)

	_, err = aliceRatchet.Receive(msg2, additionalData)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(aliceRatchet.SendingPublicKey.Bytes(), oldAlicePublicKey.Bytes()) {
		t.Error("alice's public key should have changed after DH ratchet")
	}

	msg3, _ := aliceRatchet.Send("third", additionalData)
	plaintext, err := bobRatchet.Receive(msg3, additionalData)
	if err != nil {
		t.Fatal(err)
	}

	if plaintext != "third" {
		t.Errorf("expected 'third', got '%s'", plaintext)
	}
}
