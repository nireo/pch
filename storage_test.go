package pch

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/nireo/pch/pb"
)

func setupTestStorage(t *testing.T) (*Storage, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	storage, err := NewStorage(dbPath)
	if err != nil {
		t.Fatalf("failed to create storage: %v", err)
	}

	cleanup := func() {
		storage.Close()
		os.RemoveAll(tmpDir)
	}

	return storage, cleanup
}

func TestNewStorage(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	if storage == nil {
		t.Fatal("expected storage to be non-nil")
	}

	if storage.db == nil {
		t.Fatal("expected db to be non-nil")
	}
}

func TestStoreAndGetUser(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	user := &UserRecord{
		Username:     "testuser",
		IdentityKey:  []byte("identity-key"),
		VerifyingKey: []byte("verifying-key"),
		SignedPrekey: &pb.SignedPrekey{
			PublicKey: []byte("prekey"),
			Signature: []byte("signature"),
		},
		OneTimePrekeys: []*pb.SignedPrekey{
			{PublicKey: []byte("otp1"), Signature: []byte("sig1")},
		},
		CreatedAt: time.Now(),
	}

	err := storage.StoreUser(user)
	if err != nil {
		t.Fatalf("failed to store user: %v", err)
	}

	retrieved, err := storage.GetUser("testuser")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if retrieved.Username != user.Username {
		t.Errorf("expected username %s, got %s", user.Username, retrieved.Username)
	}

	if string(retrieved.IdentityKey) != string(user.IdentityKey) {
		t.Errorf("identity keys don't match")
	}

	if string(retrieved.VerifyingKey) != string(user.VerifyingKey) {
		t.Errorf("verifying keys don't match")
	}
}

func TestGetUserNotFound(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	_, err := storage.GetUser("nonexistent")
	if err == nil {
		t.Error("expected error when getting nonexistent user")
	}
}

func TestUserExists(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	user := &UserRecord{
		Username:    "existinguser",
		IdentityKey: []byte("key"),
		CreatedAt:   time.Now(),
	}

	exists := storage.UserExists("existinguser")
	if exists {
		t.Error("user should not exist yet")
	}

	err := storage.StoreUser(user)
	if err != nil {
		t.Fatalf("failed to store user: %v", err)
	}

	exists = storage.UserExists("existinguser")
	if !exists {
		t.Error("user should exist after storing")
	}

	exists = storage.UserExists("nonexistent")
	if exists {
		t.Error("nonexistent user should not exist")
	}
}

func TestAddOTPs(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	username := "testuser"
	prekeys := []*pb.SignedPrekey{
		{PublicKey: []byte("key1"), Signature: []byte("sig1")},
		{PublicKey: []byte("key2"), Signature: []byte("sig2")},
		{PublicKey: []byte("key3"), Signature: []byte("sig3")},
	}

	err := storage.AddOTPs(username, prekeys)
	if err != nil {
		t.Fatalf("failed to add OTPs: %v", err)
	}

	count, err := storage.CountOTPs(username)
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 3 {
		t.Errorf("expected 3 OTPs, got %d", count)
	}
}

func TestPopOTP(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	username := "testuser"
	prekeys := []*pb.SignedPrekey{
		{PublicKey: []byte("key1"), Signature: []byte("sig1")},
		{PublicKey: []byte("key2"), Signature: []byte("sig2")},
	}

	err := storage.AddOTPs(username, prekeys)
	if err != nil {
		t.Fatalf("failed to add OTPs: %v", err)
	}

	prekey, err := storage.PopOTP(username)
	if err != nil {
		t.Fatalf("failed to pop OTP: %v", err)
	}

	if prekey == nil {
		t.Fatal("expected prekey to be non-nil")
	}

	count, err := storage.CountOTPs(username)
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 OTP remaining, got %d", count)
	}

	storage.PopOTP(username)

	count, err = storage.CountOTPs(username)
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 OTPs remaining, got %d", count)
	}
}

func TestPopOTPNoOTPs(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	_, err := storage.PopOTP("nonexistent")
	if err == nil {
		t.Error("expected error when popping OTP for nonexistent user")
	}

	username := "emptyuser"
	err = storage.AddOTPs(username, []*pb.SignedPrekey{})
	if err != nil {
		t.Fatalf("failed to add empty OTPs: %v", err)
	}

	_, err = storage.PopOTP(username)
	if err == nil {
		t.Error("expected error when popping from empty OTP bucket")
	}
}

func TestCountOTPsNoUser(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	count, err := storage.CountOTPs("nonexistent")
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 OTPs for nonexistent user, got %d", count)
	}
}

func TestAddMultipleOTPBatches(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	username := "testuser"

	batch1 := []*pb.SignedPrekey{
		{PublicKey: []byte("key1"), Signature: []byte("sig1")},
		{PublicKey: []byte("key2"), Signature: []byte("sig2")},
	}

	err := storage.AddOTPs(username, batch1)
	if err != nil {
		t.Fatalf("failed to add first batch: %v", err)
	}

	batch2 := []*pb.SignedPrekey{
		{PublicKey: []byte("key3"), Signature: []byte("sig3")},
		{PublicKey: []byte("key4"), Signature: []byte("sig4")},
	}

	err = storage.AddOTPs(username, batch2)
	if err != nil {
		t.Fatalf("failed to add second batch: %v", err)
	}

	count, err := storage.CountOTPs(username)
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 4 {
		t.Errorf("expected 4 OTPs, got %d", count)
	}
}

func TestStoreUserOverwrite(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	user1 := &UserRecord{
		Username: "testuser", IdentityKey: []byte("key1"), CreatedAt: time.Now(),
	}

	err := storage.StoreUser(user1)
	if err != nil {
		t.Fatalf("failed to store first user: %v", err)
	}

	user2 := &UserRecord{
		Username:    "testuser",
		IdentityKey: []byte("key2"),
		CreatedAt:   time.Now(),
	}

	err = storage.StoreUser(user2)
	if err != nil {
		t.Fatalf("failed to store second user: %v", err)
	}

	retrieved, err := storage.GetUser("testuser")
	if err != nil {
		t.Fatalf("failed to get user: %v", err)
	}

	if string(retrieved.IdentityKey) != "key2" {
		t.Errorf("expected identity key to be updated to key2")
	}
}

func TestConcurrentOTPOperations(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	username := "testuser"
	prekeys := []*pb.SignedPrekey{
		{PublicKey: []byte("key1"), Signature: []byte("sig1")},
		{PublicKey: []byte("key2"), Signature: []byte("sig2")},
		{PublicKey: []byte("key3"), Signature: []byte("sig3")},
		{PublicKey: []byte("key4"), Signature: []byte("sig4")},
		{PublicKey: []byte("key5"), Signature: []byte("sig5")},
	}

	err := storage.AddOTPs(username, prekeys)
	if err != nil {
		t.Fatalf("failed to add OTPs: %v", err)
	}

	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func() {
			_, err := storage.PopOTP(username)
			if err != nil {
				t.Logf("error popping OTP: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	count, err := storage.CountOTPs(username)
	if err != nil {
		t.Fatalf("failed to count OTPs: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 OTPs after concurrent pops, got %d", count)
	}
}
