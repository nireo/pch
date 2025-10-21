package pch

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"testing"
	"time"
)

func TestLocalStore_StoreAndGetOTPs(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	curve := ecdh.X25519()
	priv1, _ := curve.GenerateKey(rand.Reader)
	priv2, _ := curve.GenerateKey(rand.Reader)

	pub1 := priv1.PublicKey().Bytes()
	pub2 := priv2.PublicKey().Bytes()

	var key1, key2 [32]byte
	copy(key1[:], pub1)
	copy(key2[:], pub2)

	otps := map[[32]byte][]byte{
		key1: priv1.Bytes(),
		key2: priv2.Bytes(),
	}

	err = store.StoreOTPs(otps)
	if err != nil {
		t.Fatalf("failed to store OTPs: %v", err)
	}

	retrieved, err := store.GetOTPs()
	if err != nil {
		t.Fatalf("failed to get OTPs: %v", err)
	}

	if len(retrieved) != 2 {
		t.Errorf("expected 2 OTPs, got %d", len(retrieved))
	}

	if _, exists := retrieved[key1]; !exists {
		t.Error("key1 not found in retrieved OTPs")
	}

	if _, exists := retrieved[key2]; !exists {
		t.Error("key2 not found in retrieved OTPs")
	}
}

func TestLocalStore_DeleteOTP(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	curve := ecdh.X25519()
	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()

	var key [32]byte
	copy(key[:], pub)

	otps := map[[32]byte][]byte{
		key: priv.Bytes(),
	}

	store.StoreOTPs(otps)

	err = store.DeleteOTP(key)
	if err != nil {
		t.Fatalf("failed to delete OTP: %v", err)
	}

	retrieved, _ := store.GetOTPs()
	if len(retrieved) != 0 {
		t.Errorf("expected 0 OTPs after deletion, got %d", len(retrieved))
	}
}

func TestLocalStore_StoreAndGetMessages(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	chatPerson := "alice"
	msg := LocalMessage{
		Timestamp: time.Now(),
		Content:   "Hello, World!",
		FromLocal: true,
	}

	err = store.StoreMessage(chatPerson, msg)
	if err != nil {
		t.Fatalf("failed to store message: %v", err)
	}

	messages, err := store.GetMessages(chatPerson)
	if err != nil {
		t.Fatalf("failed to get messages: %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}

	if messages[0].Content != msg.Content {
		t.Errorf("expected content %q, got %q", msg.Content, messages[0].Content)
	}

	if messages[0].FromLocal {
		t.Errorf("expected sender message from local")
	}
}

func TestLocalStore_StoreMultipleMessages(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	chatPerson := "alice"
	msgs := []LocalMessage{
		{Timestamp: time.Now().Add(-2 * time.Hour), Content: "First", FromLocal: true},
		{Timestamp: time.Now().Add(-1 * time.Hour), Content: "Second", FromLocal: false},
		{Timestamp: time.Now(), Content: "Third", FromLocal: true},
	}

	err = store.StoreMessages(chatPerson, msgs)
	if err != nil {
		t.Fatalf("failed to store messages: %v", err)
	}

	retrieved, err := store.GetMessages(chatPerson)
	if err != nil {
		t.Fatalf("failed to get messages: %v", err)
	}

	if len(retrieved) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(retrieved))
	}

	if retrieved[0].Content != "First" {
		t.Errorf("expected first message to be 'First', got %q", retrieved[0].Content)
	}

	if retrieved[1].Content != "Second" {
		t.Errorf("expected second message to be 'Second', got %q", retrieved[1].Content)
	}

	if retrieved[2].Content != "Third" {
		t.Errorf("expected third message to be 'Third', got %q", retrieved[2].Content)
	}
}

func TestLocalStore_GetMessagesNonExistent(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	messages, err := store.GetMessages("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(messages) != 0 {
		t.Errorf("expected 0 messages for nonexistent chat, got %d", len(messages))
	}
}

func TestLocalStore_MessagesSortedByTimestamp(t *testing.T) {
	tmpFile := "test_store.db"
	defer os.Remove(tmpFile)

	store, err := NewLocalStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	chatPerson := "alice"
	baseTime := time.Now()

	msgs := []LocalMessage{
		{Timestamp: baseTime.Add(3 * time.Minute), Content: "Fourth", FromLocal: true},
		{Timestamp: baseTime, Content: "First", FromLocal: false},
		{Timestamp: baseTime.Add(2 * time.Minute), Content: "Third", FromLocal: true},
		{Timestamp: baseTime.Add(1 * time.Minute), Content: "Second", FromLocal: false},
	}

	err = store.StoreMessages(chatPerson, msgs)
	if err != nil {
		t.Fatalf("failed to store messages: %v", err)
	}

	retrieved, err := store.GetMessages(chatPerson)
	if err != nil {
		t.Fatalf("failed to get messages: %v", err)
	}

	if len(retrieved) != 4 {
		t.Fatalf("expected 4 messages, got %d", len(retrieved))
	}

	expected := []string{"First", "Second", "Third", "Fourth"}
	for i, msg := range retrieved {
		if msg.Content != expected[i] {
			t.Errorf("message %d: expected %q, got %q", i, expected[i], msg.Content)
		}
	}

	for i := 1; i < len(retrieved); i++ {
		if retrieved[i].Timestamp.Before(retrieved[i-1].Timestamp) {
			t.Error("messages not sorted by timestamp")
		}
	}
}
