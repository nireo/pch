package pch

import (
	"bytes"
	"encoding/gob"
	"fmt"

	bolt "go.etcd.io/bbolt"
)

var userBucket = []byte("users")
var convPrefix = []byte("con")

type Storage struct {
	db *bolt.DB
}

func EncodeEntry[T any](entry T) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(entry); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return nil, err
	}

	s := &Storage{db: db}
	err = s.ensureBuckets()
	if err != nil {
		return nil, fmt.Errorf("failed to init buckets: %s", err)
	}

	return s, nil
}

func (s *Storage) newUser(username string, publicKey []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)
		err := b.Put([]byte(username), publicKey)
		return err
	})
}

func (s *Storage) getUserKey(username string) ([]byte, error) {
	var key []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)
		v := b.Get([]byte(username))

		if v != nil {
			copy(key, v)
		}

		return fmt.Errorf("key not found for user %s", username)
	})

	return key, err
}

func (s *Storage) ensureBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(userBucket)
		return err
	})
}

func (s *Storage) Close() error {
	return s.db.Close()
}
