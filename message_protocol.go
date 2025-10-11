package pch

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"io"
	"net"
)

type MessageKind byte

const (
	MessageKindText               MessageKind = 0x01
	MessageKindKeyExchange        MessageKind = 0x02
	MessageKindJoin               MessageKind = 0x03
	MessageKindRegister           MessageKind = 0x04
	MessageKindRegisterResponse   MessageKind = 0x05
	MessageKindFetchBundle        MessageKind = 0x06
	MessageKindBundleResponse     MessageKind = 0x07
	MessageKindUploadOTPs         MessageKind = 0x08
	MessageKindUploadOTPsResponse MessageKind = 0x09
	MessageKindError              MessageKind = 0xFF
)

type UserRegistration struct {
	Username       string
	IdentityKey    []byte
	VerifyingKey   []byte
	SignedPrekey   StoredPrekey
	OneTimePrekeys []StoredPrekey
}

type BundleRequest struct {
	Username string
}

type PrekeyBundleResponse struct {
	IdentityKey     []byte
	SignedPrekey    []byte
	PrekeySignature []byte
	OneTimePrekey   []byte
}

type OTPUpload struct {
	Username       string
	OneTimePrekeys []StoredPrekey
}

// Message represents a message between two users
type Message struct {
	Kind       MessageKind
	SenderID   string
	ReceiverID string
	Payload    []byte
}

// Serialize serializes the message into a byte slice
func (m *Message) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// DeserializeMessage deserializes a byte slice into a Message
func DeserializeMessage(data []byte) (*Message, error) {
	var msg Message
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&msg); err != nil {
		return nil, err
	}

	return &msg, nil
}

func sendData(conn net.Conn, data []byte) error {
	length := uint32(len(data))
	buf := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(buf[0:4], length)
	copy(buf[4:], data)

	_, err := conn.Write(buf)
	return err
}

func receiveData(conn net.Conn) ([]byte, error) {
	var length uint32
	binary.Read(conn, binary.BigEndian, &length)

	msg := make([]byte, length)
	_, err := io.ReadFull(conn, msg)
	return msg, err
}
