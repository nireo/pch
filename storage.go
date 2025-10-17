package pch

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	pb "github.com/nireo/pch/pb"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var (
	userBucket      = []byte("users")
	convPrefix      = []byte("con")
	otpBucket       = []byte("otps")
	offlineMessages = []byte("offline")
)

type Storage struct {
	db *bolt.DB
}

type UserRecord struct {
	Username       string
	IdentityKey    []byte
	VerifyingKey   []byte
	SignedPrekey   *pb.SignedPrekey
	OneTimePrekeys []*pb.SignedPrekey
	CreatedAt      time.Time
}

type OfflineMessageKind int

const (
	EncryptedMessageKind OfflineMessageKind = iota
	InitialMessageKind
)

type OfflineMessage struct {
	Kind      OfflineMessageKind
	Message   []byte
	Timestamp time.Time
}

func encodeEntry[T any](entry T) ([]byte, error) {
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
		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(offlineMessages)
		return err
	})
}

func (s *Storage) Close() error {
	return s.db.Close()
}

func (s *Storage) AddOTPs(username string, prekeys []*pb.SignedPrekey) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		otpsBucket := tx.Bucket(otpBucket)

		uotps, err := otpsBucket.CreateBucketIfNotExists([]byte(username))
		if err != nil {
			return err
		}

		for _, prekey := range prekeys {
			encoded, err := proto.Marshal(prekey)
			if err != nil {
				return err
			}

			err = uotps.Put(prekey.PublicKey, encoded)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

func (s *Storage) PopOTP(username string) (*pb.SignedPrekey, error) {
	prekey := &pb.SignedPrekey{}

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

		err := proto.Unmarshal(v, prekey)
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

		// TODO: refactor this to use the proto definitions as well.
		data, err := encodeEntry(user)
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

func (s *Storage) GetUserMessages(username string) ([]OfflineMessage, error) {
	var messages []OfflineMessage
	return messages, nil
}

func (s *Storage) AddUserMessage(
	storedMessage OfflineMessage,
	toUsername, fromUsername string,
) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(offlineMessages)

		uBucket, err := b.CreateBucketIfNotExists([]byte(toUsername))
		if err != nil {
			return fmt.Errorf("failed to create user messages bucket: %s", err)
		}

		data, err := encodeEntry(storedMessage)
		if err != nil {
			return fmt.Errorf("failed to encode message")
		}

		err = uBucket.Put([]byte(fromUsername), data)
		return err
	})
}
