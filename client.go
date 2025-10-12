package pch

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"net"
	"sync"
	"time"
)

type ChatClient struct {
	conn           *MessageConn
	id             string
	User           *X3DHUser
	conversations  map[string]*Conversation
	mu             sync.RWMutex
	bundleRequests map[string]chan *PrekeyBundle
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

func (c *ChatClient) Register() error {
	if err := c.User.GeneratePrekeys(true); err != nil {
		return fmt.Errorf("failed to generate prekeys", err)
	}

	signedPrekey := StoredPrekey{
		PublicKey: c.User.SignedPrekeyPublic.Bytes(),
		Signature: ed25519.Sign(c.User.SigningKey, c.User.SignedPrekeyPublic.Bytes()),
		CreatedAt: time.Now(),
	}

	// generate many otps
	otps := make([]StoredPrekey, 100)
	curve := ecdh.X25519()

	for i := range 100 {
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate OTP: %w", err)
		}

		otps[i] = StoredPrekey{
			PublicKey: otpPriv.PublicKey().Bytes(),
			Signature: ed25519.Sign(c.User.SigningKey, otpPriv.PublicKey().Bytes()),
			CreatedAt: time.Now(),
		}
	}

	reg := UserRegistration{
		Username:       c.id,
		IdentityKey:    c.User.IdentityPublicKey.Bytes(),
		VerifyingKey:   c.User.VerifyingKey,
		SignedPrekey:   signedPrekey,
		OneTimePrekeys: otps,
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(reg); err != nil {
		return fmt.Errorf("failed to encode registration: %w", err)
	}

	msg := &Message{
		Kind:     MessageKindRegister,
		SenderID: c.id,
		Payload:  buf.Bytes(),
	}

	data, err := msg.Serialize()
	if err != nil {
		return err
	}

	if err := c.conn.Send(data); err != nil {
		return err
	}

	respData, err := c.conn.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive registration response: %w", err)
	}

	respMsg, err := DeserializeMessage(respData)
	if err != nil {
		return err
	}

	if respMsg.Kind == MessageKindError {
		return fmt.Errorf("registration failed: %s", string(respMsg.Payload))
	}

	fmt.Printf("Registration successful: %s\n", string(respMsg.Payload))
	return nil
}

func (c *ChatClient) FetchBundle(username string) (*PrekeyBundle, error) {
	request := BundleRequest{Username: username}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(request); err != nil {
		return nil, err
	}

	msg := &Message{
		Kind:     MessageKindFetchBundle,
		SenderID: c.id,
		Payload:  buf.Bytes(),
	}

	data, err := msg.Serialize()
	if err != nil {
		return nil, err
	}

	if err := c.conn.Send(data); err != nil {
		return nil, err
	}

	return c.waitForBundle(username)
}

func (c *ChatClient) waitForBundle(username string) (*PrekeyBundle, error) {
	// Create a response channel for this specific request
	respChan := make(chan *PrekeyBundle, 1)
	errChan := make(chan error, 1)

	c.mu.Lock()
	if c.bundleRequests == nil {
		c.bundleRequests = make(map[string]chan *PrekeyBundle)
	}
	c.bundleRequests[username] = respChan
	c.mu.Unlock()

	// Wait for response with timeout
	select {
	case bundle := <-respChan:
		return bundle, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(10 * time.Second):
		c.mu.Lock()
		delete(c.bundleRequests, username)
		c.mu.Unlock()
		return nil, fmt.Errorf("timeout waiting for bundle")
	}
}

func (c *ChatClient) handleBundleResponse(msg *Message) {
	var bundleResp PrekeyBundleResponse
	if err := gob.NewDecoder(bytes.NewBuffer(msg.Payload)).Decode(&bundleResp); err != nil {
		return
	}

	identityKey, _ := ecdh.X25519().NewPublicKey(bundleResp.IdentityKey)
	signedPrekey, _ := ecdh.X25519().NewPublicKey(bundleResp.SignedPrekey)

	bundle := &PrekeyBundle{
		IdentityKey:     identityKey,
		SignedPrekey:    signedPrekey,
		PrekeySignature: bundleResp.PrekeySignature,
	}

	if len(bundleResp.OneTimePrekey) > 0 {
		oneTimePrekey, _ := ecdh.X25519().NewPublicKey(bundleResp.OneTimePrekey)
		bundle.OneTimePrekey = oneTimePrekey
	}

	c.mu.Lock()
	if c.bundleRequests != nil {
		for username, ch := range c.bundleRequests {
			select {
			case ch <- bundle:
				delete(c.bundleRequests, username)
			default:
			}
			break
		}
	}
	c.mu.Unlock()
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
	case MessageKindBundleResponse:
		c.handleBundleResponse(msg)
	case MessageKindError:
		fmt.Printf("Error from server: %s\n", string(msg.Payload))
	}
}

func (c *ChatClient) handleKeyExchange(msg *Message) {
	var initMsg InitialMessage
	buf := bytes.NewBuffer(msg.Payload)
	gob.NewDecoder(buf).Decode(&initMsg)

	sharedSecret, _ := c.User.calculateSharedSecretAsReceiver(initMsg)

	ratchet, _ := NewRatchetState()
	copy(ratchet.RootKey[:], sharedSecret)

	ad := c.User.additionalInformation(initMsg.IdentityKey)

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

	ad := c.User.additionalInformation(bundle.IdentityKey)

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

func (c *ChatClient) InitiateChatWithUser(recipientID string) error {
	bundle, err := c.FetchBundle(recipientID)
	if err != nil {
		return fmt.Errorf("failed to fetch bundle: %w", err)
	}

	return c.InitiateChat(recipientID, *bundle)
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
