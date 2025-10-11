package pch

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

var userBucket = []byte("users")
var convPrefix = []byte("con")
var otpBucket = []byte("otps") // one time prekeys

type Storage struct {
	db *bolt.DB
}

type StoredPrekey struct {
	PublicKey []byte
	Signature []byte
	CreatedAt time.Time
}

func (sp *StoredPrekey) Encode() []byte {
	sigLen := uint16(len(sp.Signature))
	timestamp := sp.CreatedAt.Unix()

	buf := make([]byte, 32+2+len(sp.Signature)+8)

	copy(buf[0:32], sp.PublicKey)                                  // 32 bytes
	binary.BigEndian.PutUint16(buf[32:34], sigLen)                 // 2 bytes
	copy(buf[34:34+sigLen], sp.Signature)                          // N bytes
	binary.BigEndian.PutUint64(buf[34+sigLen:], uint64(timestamp)) // 8 bytes

	return buf
}

func DecodeStoredPrekey(data []byte) (*StoredPrekey, error) {
	if len(data) < 34 {
		return nil, fmt.Errorf("invalid data length")
	}

	pubKey := data[0:32]
	sigLen := binary.BigEndian.Uint16(data[32:34])

	if len(data) < 34+int(sigLen)+8 {
		return nil, fmt.Errorf("invalid data length")
	}

	signature := data[34 : 34+sigLen]
	timestamp := int64(binary.BigEndian.Uint64(data[34+sigLen:]))

	return &StoredPrekey{
		PublicKey: pubKey,
		Signature: signature,
		CreatedAt: time.Unix(timestamp, 0),
	}, nil
}

type UserRecord struct {
	Username       string
	IdentityKey    []byte // stored as bytes for JSON serialization
	VerifyingKey   []byte
	SignedPrekey   *StoredPrekey
	OneTimePrekeys []StoredPrekey
	CreatedAt      time.Time
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
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(otpBucket)
		return err
	})
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) AddOTPs(username string, prekeys []StoredPrekey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		otpsBucket := tx.Bucket(otpBucket)

		uotps, err := otpsBucket.CreateBucketIfNotExists([]byte(username))
		if err != nil {
			return err
		}

		for _, prekey := range prekeys {
			encoded := prekey.Encode()

			err = uotps.Put(prekey.PublicKey, encoded)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *Storage) PopOTP(username string) (*StoredPrekey, error) {
	var prekey *StoredPrekey

	err := s.db.Update(func(tx *bolt.Tx) error {
		otpsBucket := tx.Bucket(otpBucket)
		userOTPBucket := otpsBucket.Bucket([]byte(username))

		if userOTPBucket == nil {
			return fmt.Errorf("no otps for user %s", username)
		}

		c := userOTPBucket.Cursor()

		k, v := c.First()
		if k == nil {
			return fmt.Errorf("no OTPs available")
		}

		var err error
		prekey, err = DecodeStoredPrekey(v)
		if err != nil {
			return err
		}

		return userOTPBucket.Delete(k)
	})

	return prekey, err
}

func (s *Storage) CountOTPs(username string) (int, error) {
	var count int

	err := s.db.View(func(tx *bolt.Tx) error {
		otpsBucket := tx.Bucket(otpBucket)
		userOTPBucket := otpsBucket.Bucket([]byte(username))

		if userOTPBucket == nil {
			return nil
		}

		userOTPBucket.ForEach(func(k, v []byte) error {
			count++
			return nil
		})

		return nil
	})

	return count, err
}

func (s *Storage) UserExists(username string) bool {
	exists := false
	s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)
		v := b.Get([]byte(username))
		exists = (v != nil)
		return nil
	})

	return exists
}

func (s *Storage) StoreUser(user *UserRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)

		data, err := EncodeEntry(user)
		if err != nil {
			return fmt.Errorf("failed to encode user: %w", err)
		}

		return b.Put([]byte(user.Username), data)
	})
}

func (s *Storage) GetUser(username string) (*UserRecord, error) {
	var user UserRecord

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(userBucket)
		v := b.Get([]byte(username))

		if v == nil {
			return fmt.Errorf("user not found: %s", username)
		}

		buf := bytes.NewBuffer(v)
		dec := gob.NewDecoder(buf)
		return dec.Decode(&user)
	})

	return &user, err
}
