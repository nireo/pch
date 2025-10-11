package pch

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"sync"
)

type ChatClient struct {
	conn          *MessageConn
	id            string
	User          *X3DHUser
	conversations map[string]*Conversation
	mu            sync.RWMutex
}

func NewChatClient(serverAddr, username string) (*ChatClient, error) {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	user, err := NewX3DFUser(username)
	if err != nil {
		return nil, err
	}

	mc := &MessageConn{
		conn: conn,
		w:    bufio.NewWriter(conn),
		r:    bufio.NewReader(conn),
	}

	client := &ChatClient{
		conn:          mc,
		id:            username,
		User:          user,
		conversations: make(map[string]*Conversation),
	}

	joinMsg := &Message{
		Kind:     MessageKindJoin,
		SenderID: username,
	}

	data, err := joinMsg.Serialize()
	if err != nil {
		return nil, err
	}

	err = mc.Send(data)
	if err != nil {
		return nil, nil
	}

	go client.readMessages()
	return client, nil
}

func (c *ChatClient) readMessages() {
	for {
		data, err := c.conn.Recv()
		if err != nil {
			return
		}

		msg, err := DeserializeMessage(data)
		if err != nil {
			continue
		}

		c.handleMessage(msg)
	}
}

func (c *ChatClient) handleMessage(msg *Message) {
	switch msg.Kind {
	case MessageKindKeyExchange:
		c.handleKeyExchange(msg)
	case MessageKindText:
		c.handleTextMessage(msg)
	}
}

func (c *ChatClient) handleKeyExchange(msg *Message) {
	var initMsg InitialMessage
	buf := bytes.NewBuffer(msg.Payload)
	gob.NewDecoder(buf).Decode(&initMsg)

	sharedSecret, _ := c.User.calculateSharedSecretAsReceiver(initMsg)

	ratchet, _ := NewRatchetState()
	copy(ratchet.RootKey[:], sharedSecret)

	ad, _ := c.User.additionalInformation(initMsg.IdentityKey)

	c.mu.Lock()
	c.conversations[msg.SenderID] = &Conversation{
		RemoteIdentityKey: initMsg.IdentityKey,
		SessionID:         []byte(msg.SenderID),
		Ratchet:           ratchet,
		AdditionalData:    ad,
	}
	c.mu.Unlock()
}

func (c *ChatClient) handleTextMessage(msg *Message) {
	c.mu.RLock()
	conv, ok := c.conversations[msg.SenderID]
	c.mu.RUnlock()

	if !ok {
		return
	}

	var ratchetMsg RatchetMessage
	buf := bytes.NewBuffer(msg.Payload)
	gob.NewDecoder(buf).Decode(&ratchetMsg)

	plaintext, _ := conv.Ratchet.Receive(&ratchetMsg, conv.AdditionalData)
	fmt.Printf("[%s]: %s\n", msg.SenderID, plaintext)
}

func (c *ChatClient) InitiateChat(recipientID string, bundle PrekeyBundle) error {
	c.User.GenerateEphemeralKey()

	initMsg, sharedSecret, err := c.User.CreateInitialMessage(bundle, nil)
	if err != nil {
		return err
	}

	ratchet, _ := NewRatchetState()
	copy(ratchet.RootKey[:], sharedSecret)

	ad, _ := c.User.additionalInformation(bundle.IdentityKey)

	c.mu.Lock()
	c.conversations[recipientID] = &Conversation{
		RemoteIdentityKey: bundle.IdentityKey,
		SessionID:         []byte(recipientID),
		Ratchet:           ratchet,
		AdditionalData:    ad,
	}
	c.mu.Unlock()

	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(initMsg)

	msg := &Message{
		Kind:       MessageKindKeyExchange,
		SenderID:   c.id,
		ReceiverID: recipientID,
		Payload:    buf.Bytes(),
	}

	data, _ := msg.Serialize()
	return c.conn.Send(data)
}

func (c *ChatClient) SendMessage(recipientID, text string) error {
	c.mu.RLock()
	conv, ok := c.conversations[recipientID]
	c.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no conversation with %s", recipientID)
	}

	ratchetMsg, err := conv.Ratchet.Send(text, conv.AdditionalData)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	gob.NewEncoder(&buf).Encode(ratchetMsg)

	msg := &Message{
		Kind:       MessageKindText,
		SenderID:   c.id,
		ReceiverID: recipientID,
		Payload:    buf.Bytes(),
	}

	data, _ := msg.Serialize()
	return c.conn.Send(data)
}
