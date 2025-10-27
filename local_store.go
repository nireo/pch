package pch

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	localOtpBucket  = []byte("otps")
	localChatBucket = []byte("chats")
	localKeysBucket = []byte("keys")

	signingKey   = []byte("skey")
	identityKey  = []byte("idk")
	signedPreKey = []byte("spkey")
	verifyingKey = []byte("vkey")

	ErrUserNotFound = errors.New("keys not found for user")
	ErrMissingKeys  = errors.New("missing keys")
)

// LocalStore stores the chats between different users. Generally, in these end-to-end encrypted
// chat applications these messages are stored locally unencrypted as usage assumes that the device
// itself is secure. The local store is also responsible for storing the one-time prekeys used.
type LocalStore struct {
	db *bolt.DB
}

// LocalMessage represents a message stored in the local store.
type LocalMessage struct {
	Timestamp time.Time
	Content   string
	FromLocal bool // this signifies if the sender is the local user or the other user
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
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(localKeysBucket)
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

// DeleteOTP deletes the OTP for the given public key from the local store.
func (l *LocalStore) DeleteOTP(pubKey [32]byte) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localOtpBucket)
		return b.Delete(pubKey[:])
	})
}

// StoreMessage stores a message for the given chat person.
func (l *LocalStore) StoreMessage(chatPerson string, msg LocalMessage) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localChatBucket)
		chatB, err := b.CreateBucketIfNotExists([]byte(chatPerson))
		if err != nil {
			return err
		}

		data, err := encodeGob(msg)
		if err != nil {
			return err
		}

		var timestampKey [8]byte
		binary.BigEndian.PutUint64(timestampKey[:], uint64(msg.Timestamp.UnixNano()))
		return chatB.Put(timestampKey[:], data)
	})
}

// StoreMessages stores multiple messages for the given chat person.
func (l *LocalStore) StoreMessages(chatPerson string, msgs []LocalMessage) error {
	return l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localChatBucket)
		chatB, err := b.CreateBucketIfNotExists([]byte(chatPerson))
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			data, err := encodeGob(msg)
			if err != nil {
				return err
			}

			var timestampKey [8]byte
			binary.BigEndian.PutUint64(timestampKey[:], uint64(msg.Timestamp.UnixNano()))
			err = chatB.Put(timestampKey[:], data)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// GetMessages retrieves all messages for the given chat person.
func (l *LocalStore) GetMessages(chatPerson string) ([]LocalMessage, error) {
	messages := []LocalMessage{}
	err := l.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(localChatBucket)
		chatB := b.Bucket([]byte(chatPerson))
		if chatB == nil {
			return nil // no messages
		}

		return chatB.ForEach(func(k, v []byte) error {
			var msg LocalMessage
			err := decodeGob(v, &msg)
			if err != nil {
				return err
			}
			messages = append(messages, msg)
			return nil
		})
	})
	return messages, err
}

// StoreX3DHState stores the private keys for the X3DH state such that it's persisted between
// sessions. It stores only the private keys since the public keys can easily be derived from those.
func (l *LocalStore) StoreX3DHState(state *X3DHUser) error {
	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localKeysBucket)

		uBucket, err := b.CreateBucketIfNotExists([]byte(state.Username))
		if err != nil {
			return err
		}

		if state.IdentityPrivateKey == nil {
			return ErrMissingKeys
		}

		err = uBucket.Put(identityKey, state.IdentityPrivateKey.Bytes())
		if err != nil {
			return err
		}

		if state.SignedPrekeyPrivate != nil {
			err = uBucket.Put(signedPreKey, state.SignedPrekeyPrivate.Bytes())
			if err != nil {
				return err
			}
		}

		err = uBucket.Put(signingKey, state.SigningKey)
		if err != nil {
			return err
		}

		err = uBucket.Put(verifyingKey, state.VerifyingKey)
		if err != nil {
			return err
		}

		return nil
	})

	return err
}

// GetX3DHState reads a given user's state from the database and constructs the given state
func (l *LocalStore) GetX3DHState(username string) (*X3DHUser, error) {
	state := &X3DHUser{}
	err := l.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(localKeysBucket)
		uBucket := b.Bucket([]byte(username))
		if uBucket == nil {
			return ErrUserNotFound
		}

		v := uBucket.Get(identityKey)
		if v == nil {
			return ErrMissingKeys
		}

		var err error
		state.IdentityPrivateKey, err = ecdh.X25519().NewPrivateKey(v)
		if err != nil {
			return err
		}
		state.IdentityPublicKey = state.IdentityPrivateKey.PublicKey()

		v = uBucket.Get(signedPreKey)
		if v != nil {
			state.SignedPrekeyPrivate, err = ecdh.X25519().NewPrivateKey(v)
			if err != nil {
				return err
			}
			state.SignedPrekeyPublic = state.SignedPrekeyPrivate.PublicKey()
		}

		v = uBucket.Get(signingKey)
		if v == nil {
			return ErrMissingKeys
		}
		state.SigningKey = append([]byte(nil), v...)

		v = uBucket.Get(verifyingKey)
		if v == nil {
			return ErrMissingKeys
		}
		state.VerifyingKey = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	state.Username = username
	return state, nil
}
