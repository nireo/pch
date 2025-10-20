package pch

import (
	"crypto/ecdh"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var (
	localOtpBucket  = []byte("otps")
	localChatBucket = []byte("chats")
)

// LocalStore stores the chats between different users. Generally, in these end-to-end encrypted
// chat applications these messages are stored locally unencrypted as usage assumes that the device
// itself is secure. The local store is also responsible for storing the one-time prekeys used.
type LocalStore struct {
	db *bolt.DB
}

// Close closes the local store database.
func (l *LocalStore) Close() error {
	return l.db.Close()
}

// ensureBuckets makes sure the necessary buckets exist.
func (l *LocalStore) ensureBuckets() error {
	return l.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(localOtpBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(localChatBucket)
		return err
	})
}

// NewLocalStore creates a new local store at the given path.
func NewLocalStore(path string) (*LocalStore, error) {
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	l := &LocalStore{db: db}
	err = l.ensureBuckets()
	if err != nil {
		return nil, fmt.Errorf("failed to init local store buckets: %s", err)
	}
	return l, nil
}

// StoreOTP stores a map of otps in the local store.
func (l *LocalStore) StoreOTPs(otps map[[32]byte][]byte) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localOtpBucket)
		for k, v := range otps {
			err := b.Put(k[:], v)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetOTPs retrieves all stored OTPs from the local store.
func (l *LocalStore) GetOTPs() (map[[32]byte]*ecdh.PrivateKey, error) {
	otps := make(map[[32]byte]*ecdh.PrivateKey)
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(localOtpBucket)
		return b.ForEach(func(k, v []byte) error {
			var keyArr [32]byte
			copy(keyArr[:], k)

			// i checked the source code and this clones it so no lifetime issues
			privKey, err := ecdh.X25519().NewPrivateKey(v)
			if err != nil {
				return err
			}
			otps[keyArr] = privKey
			return nil
		})
	})
	return otps, err
}
