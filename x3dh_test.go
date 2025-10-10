package pch

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestNewX3DFUser(t *testing.T) {
	user, err := NewX3DFUser("testuser")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	if user.IdentityPrivateKey == nil {
		t.Error("Identity private key should not be nil")
	}

	if user.IdentityPublicKey == nil {
		t.Error("Identity public key should not be nil")
	}

	if user.SigningKey == nil {
		t.Error("Signing key should not be nil")
	}

	if user.VerifyingKey == nil {
		t.Error("Verifying key should not be nil")
	}

	if len(user.SigningKey) != ed25519.PrivateKeySize {
		t.Errorf("Expected signing key size %d, got %d", ed25519.PrivateKeySize, len(user.SigningKey))
	}
}

func TestGenerateEphemeralKey(t *testing.T) {
	user, err := NewX3DFUser("testuser")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	if user.EphemeralPrivateKey != nil {
		t.Error("Ephemeral private key should be nil initially")
	}

	err = user.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("Failed to generate ephemeral key: %v", err)
	}

	if user.EphemeralPrivateKey == nil {
		t.Error("Ephemeral private key should not be nil after generation")
	}

	if user.EphemeralPublicKey == nil {
		t.Error("Ephemeral public key should not be nil after generation")
	}
}

func TestGeneratePrekeys(t *testing.T) {
	user, err := NewX3DFUser("testuser")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	err = user.GeneratePrekeys(false)
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	if user.SignedPrekeyPrivate == nil {
		t.Error("Signed prekey private should not be nil")
	}

	if user.SignedPrekeyPublic == nil {
		t.Error("Signed prekey public should not be nil")
	}

	if user.OneTimePrekeyPrivate != nil {
		t.Error("One-time prekey private should be nil when oneTime=false")
	}

	err = user.GeneratePrekeys(true)
	if err != nil {
		t.Fatalf("Failed to generate prekeys with one-time: %v", err)
	}

	if user.OneTimePrekeyPrivate == nil {
		t.Error("One-time prekey private should not be nil when oneTime=true")
	}

	if user.OneTimePrekeyPublic == nil {
		t.Error("One-time prekey public should not be nil when oneTime=true")
	}
}

func TestCreatePrekeyBundle(t *testing.T) {
	user, err := NewX3DFUser("testuser")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	_, err = user.CreatePrekeyBundle()
	if err == nil {
		t.Error("Expected error when creating bundle without prekeys")
	}

	err = user.GeneratePrekeys(true)
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	bundle, err := user.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create prekey bundle: %v", err)
	}

	if bundle.IdentityKey == nil {
		t.Error("Bundle identity key should not be nil")
	}

	if bundle.SignedPrekey == nil {
		t.Error("Bundle signed prekey should not be nil")
	}

	if bundle.PrekeySignature == nil {
		t.Error("Bundle prekey signature should not be nil")
	}

	if bundle.OneTimePrekey == nil {
		t.Error("Bundle one-time prekey should not be nil when generated")
	}

	if !ed25519.Verify(user.VerifyingKey, bundle.SignedPrekey.Bytes(), bundle.PrekeySignature) {
		t.Error("Prekey signature verification failed")
	}
}

func TestVerifyPrekeySignature(t *testing.T) {
	user, err := NewX3DFUser("testuser")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	err = user.GeneratePrekeys(false)
	if err != nil {
		t.Fatalf("Failed to generate prekeys: %v", err)
	}

	bundle, err := user.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create bundle: %v", err)
	}

	if !verifyPrekeySignature(*bundle, user.VerifyingKey) {
		t.Error("Valid signature failed verification")
	}

	wrongUser, _ := NewX3DFUser("wrong")
	if verifyPrekeySignature(*bundle, wrongUser.VerifyingKey) {
		t.Error("Invalid signature passed verification")
	}
}

func TestX3DHKeyAgreement(t *testing.T) {
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
		t.Fatalf("Failed to generate Bob's prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create Bob's bundle: %v", err)
	}

	initialMsg, aliceSecret, err := alice.CreateInitialMessage(*bobBundle, []byte("Hello Bob!"))
	if err != nil {
		t.Fatalf("Failed to create initial message: %v", err)
	}

	if initialMsg.IdentityKey == nil {
		t.Error("Initial message identity key should not be nil")
	}

	if initialMsg.EphemeralKey == nil {
		t.Error("Initial message ephemeral key should not be nil")
	}

	if len(initialMsg.Payload) == 0 {
		t.Error("Initial message payload should not be empty")
	}

	bobSecret, err := bob.calculateSharedSecretAsReceiver(*initialMsg)
	if err != nil {
		t.Fatalf("Failed to calculate Bob's shared secret: %v", err)
	}

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Error("Shared secrets don't match")
	}

	if len(aliceSecret) != 32 {
		t.Errorf("Expected shared secret length 32, got %d", len(aliceSecret))
	}

	if alice.EphemeralPrivateKey != nil {
		t.Error("Alice's ephemeral private key should be deleted after key agreement")
	}
}

func TestX3DHKeyAgreementWithoutOneTimePrekey(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("Failed to create Alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("Failed to create Bob: %v", err)
	}

	err = bob.GeneratePrekeys(false)
	if err != nil {
		t.Fatalf("Failed to generate Bob's prekeys: %v", err)
	}

	bobBundle, err := bob.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("Failed to create Bob's bundle: %v", err)
	}

	initialMsg, aliceSecret, err := alice.CreateInitialMessage(*bobBundle, []byte("Hello Bob!"))
	if err != nil {
		t.Fatalf("Failed to create initial message: %v", err)
	}

	bobSecret, err := bob.calculateSharedSecretAsReceiver(*initialMsg)
	if err != nil {
		t.Fatalf("Failed to calculate Bob's shared secret: %v", err)
	}

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Error("Shared secrets don't match without one-time prekey")
	}
}

func TestKDF(t *testing.T) {
	input := []byte("test input material")
	info := "test info"

	output, err := KDF(input, info)
	if err != nil {
		t.Fatalf("KDF failed: %v", err)
	}

	if len(output) != 32 {
		t.Errorf("Expected KDF output length 32, got %d", len(output))
	}

	output2, err := KDF(input, info)
	if err != nil {
		t.Fatalf("KDF failed on second call: %v", err)
	}

	if !bytes.Equal(output, output2) {
		t.Error("KDF should be deterministic")
	}

	output3, err := KDF(input, "different info")
	if err != nil {
		t.Fatalf("KDF failed with different info: %v", err)
	}

	if bytes.Equal(output, output3) {
		t.Error("KDF should produce different output for different info")
	}
}

func TestDH(t *testing.T) {
	alice, err := NewX3DFUser("alice")
	if err != nil {
		t.Fatalf("Failed to create Alice: %v", err)
	}

	bob, err := NewX3DFUser("bob")
	if err != nil {
		t.Fatalf("Failed to create Bob: %v", err)
	}

	secret1, err := DH(alice.IdentityPrivateKey, bob.IdentityPublicKey)
	if err != nil {
		t.Fatalf("DH failed: %v", err)
	}

	secret2, err := DH(bob.IdentityPrivateKey, alice.IdentityPublicKey)
	if err != nil {
		t.Fatalf("DH failed: %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Error("DH should produce same shared secret from both sides")
	}

	if len(secret1) != 32 {
		t.Errorf("Expected DH output length 32, got %d", len(secret1))
	}
}
