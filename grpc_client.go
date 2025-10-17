package pch

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"sync"

	pb "github.com/nireo/pch/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RpcClient is a gRPC client for the ChatService. It also takes care of handling encryption etc
type RpcClient struct {
	conn          *grpc.ClientConn
	srv           pb.ChatServiceClient
	user          *X3DHUser
	username      string
	conversations map[string]*Conversation
	mu            sync.RWMutex
	stream        pb.ChatService_MessageStreamClient
	streamMu      sync.Mutex

	// a function to capture the messages for testing purposes
	onMessageReceived func(from, message string)
}

// NewRpcClient creates a new gRPC client connected to the specified address.
func NewRpcClient(addr string, username string) (*RpcClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("error making client: %v", err)
	}

	user, err := NewX3DFUser(username)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	return &RpcClient{
		conn:          conn,
		srv:           pb.NewChatServiceClient(conn),
		user:          user,
		username:      username,
		conversations: make(map[string]*Conversation),
	}, nil
}

// Close closes the gRPC client connection.
func (c *RpcClient) Close() error {
	c.streamMu.Lock()
	if c.stream != nil {
		c.stream.CloseSend()
	}
	c.streamMu.Unlock()
	return c.conn.Close()
}

// generateOtps generates n one-time prekeys.
func (c *RpcClient) generateOtps(n int) ([]*pb.SignedPrekey, error) {
	otps := make([]*pb.SignedPrekey, n)
	curve := ecdh.X25519()

	for i := 0; i < n; i++ {
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate otp: %w", err)
		}

		otps[i] = &pb.SignedPrekey{
			PublicKey: otpPriv.PublicKey().Bytes(),
			Signature: ed25519.Sign(
				c.user.SigningKey,
				otpPriv.PublicKey().Bytes(),
			),
			CreatedAt: timestamppb.Now(),
		}
	}

	return otps, nil
}

// Register registers the user with the server using the provided username. It generates prekeys and
// one-time prekeys as part of the registration process.
func (c *RpcClient) Register(ctx context.Context, username string) error {
	err := c.user.GeneratePrekeys(true)
	if err != nil {
		return fmt.Errorf("failed to generate prekeys, %v", err)
	}

	signedPrekey := &pb.SignedPrekey{
		PublicKey: c.user.SignedPrekeyPublic.Bytes(),
		Signature: ed25519.Sign(
			c.user.SigningKey,
			c.user.SignedPrekeyPublic.Bytes(),
		),
		CreatedAt: timestamppb.Now(),
	}

	otps, err := c.generateOtps(0)
	if err != nil {
		return fmt.Errorf("failed to generate otps: %v", err)
	}

	req := &pb.RegisterRequest{
		Username:       username,
		IdentityKey:    c.user.IdentityPublicKey.Bytes(),
		VerifyingKey:   c.user.VerifyingKey,
		SignedPrekey:   signedPrekey,
		OneTimePrekeys: otps,
	}
	_, err = c.srv.Register(ctx, req)
	return err
}

// FetchBundle fetches the prekey bundle for the specified username from the server.
func (c *RpcClient) FetchBundle(ctx context.Context, username string) (*pb.PrekeyBundle, error) {
	req := &pb.FetchBundleRequest{
		Username: username,
	}

	resp, err := c.srv.FetchBundle(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %v", err)
	}

	return resp.Bundle, nil
}

// UploadOTPs uploads one-time prekeys to the server.
func (c *RpcClient) UploadOTPs(ctx context.Context, count int) error {
	otps, err := c.generateOtps(count)
	if err != nil {
		return fmt.Errorf("failed to generate otps: %v", err)
	}

	req := &pb.UploadOTPsRequest{
		Username:       c.username,
		OneTimePrekeys: otps,
	}

	resp, err := c.srv.UploadOTPs(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to upload otps: %v", err)
	}

	log.Printf("uploaded %d otps (total: %d)", resp.UploadedCount, resp.TotalOtps)
	return nil
}

// StartChat initiates the message stream and joins the chat.
func (c *RpcClient) StartChat(
	ctx context.Context,
	username string,
) (pb.ChatService_MessageStreamClient, error) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	if c.stream != nil {
		return c.stream, nil
	}

	stream, err := c.srv.MessageStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create stream: %v", err)
	}

	c.stream = stream

	joinMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_Join{
			Join: &pb.JoinRequest{
				Username: username,
			},
		},
	}

	if err := stream.Send(joinMsg); err != nil {
		return nil, fmt.Errorf("failed to send join message: %v", err)
	}

	go c.receiveMessages(stream)
	return stream, nil
}

// receiveMessages handles incoming messages from the stream.
func (c *RpcClient) receiveMessages(stream pb.ChatService_MessageStreamClient) {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Println("Stream closed by server")
			return
		}

		if err != nil {
			log.Printf("Error receiving message: %v", err)
			return
		}

		c.handleServerMessage(msg)
	}
}

// handleServerMessage processes incoming server messages.
func (c *RpcClient) handleServerMessage(msg *pb.ServerMessage) {
	switch v := msg.MessageType.(type) {
	case *pb.ServerMessage_JoinResponse:
		log.Printf("Join response: %s", v.JoinResponse.Message)

	case *pb.ServerMessage_EncryptedMessage:
		c.handleEncryptedMessage(v.EncryptedMessage)

	case *pb.ServerMessage_KeyExchange:
		c.handleKeyExchange(v.KeyExchange)

	case *pb.ServerMessage_Heartbeat:
		if v.Heartbeat.Timestamp != nil {
			log.Printf("Heartbeat received at %v", v.Heartbeat.Timestamp.AsTime())
		} else {
			log.Printf("Heartbeat received")
		}

	default:
		log.Printf("Unknown server message type: %T", v)
	}
}

// handleEncryptedMessage processes incoming encrypted messages.
func (c *RpcClient) handleEncryptedMessage(msg *pb.EncryptedMessage) {
	c.mu.RLock()
	conv, ok := c.conversations[msg.SenderId]
	c.mu.RUnlock()

	if !ok {
		log.Printf("No conversation found for %s", msg.SenderId)
		return
	}

	if msg.RatchetMessage == nil {
		log.Printf("Encrypted message missing ratchet message")
		return
	}

	var pubKeyBytes [32]byte
	copy(pubKeyBytes[:], msg.RatchetMessage.PublicKey)

	counter := uint64(msg.RatchetMessage.MessageNumber)

	var nonce [12]byte
	if len(msg.RatchetMessage.Nonce) != 12 {
		log.Printf("Invalid nonce length: expected 12, got %d", len(msg.RatchetMessage.Nonce))
		return
	}
	copy(nonce[:], msg.RatchetMessage.Nonce)

	header := RatchetMessageHeader{
		PublicKey: pubKeyBytes,
		Counter:   counter,
		Nonce:     nonce,
	}

	ratchetMsg := &RatchetMessage{
		Header:     header,
		Ciphertext: msg.RatchetMessage.Ciphertext,
	}

	plaintext, err := conv.Ratchet.Receive(ratchetMsg, conv.AdditionalData)
	if err != nil {
		log.Printf("failed to decrypt message: %v", err)
		return
	}

	// log the message for testing purposes
	if c.onMessageReceived != nil {
		c.onMessageReceived(msg.SenderId, plaintext)
	}

	fmt.Printf("[%s]: %s\n", msg.SenderId, plaintext)
}

// SendMessage sends an encrypted message to the specified recipient.
func (c *RpcClient) SendMessage(recipientID, text string) error {
	c.mu.RLock()
	conv, ok := c.conversations[recipientID]
	c.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no conversation with %s", recipientID)
	}

	ratchetMsg, err := conv.Ratchet.Send(text, conv.AdditionalData)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %v", err)
	}

	pbRatchetMsg := &pb.RatchetMessage{
		PublicKey: ratchetMsg.Header.PublicKey[:],
		PreviousChainLength: int32(
			conv.Ratchet.ReceivingCounter,
		),
		MessageNumber: int32(ratchetMsg.Header.Counter),
		Ciphertext:    ratchetMsg.Ciphertext,
		Nonce:         ratchetMsg.Header.Nonce[:],
	}

	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream not initialized")
	}

	clientMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_EncryptedMessage{
			EncryptedMessage: &pb.EncryptedMessage{
				SenderId:       c.username,
				ReceiverId:     recipientID,
				RatchetMessage: pbRatchetMsg,
				Timestamp:      timestamppb.Now(),
			},
		},
	}

	if err := stream.Send(clientMsg); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

func (c *RpcClient) InitiateChat(ctx context.Context, recipientID string) error {
	bundle, err := c.FetchBundle(ctx, recipientID)
	if err != nil {
		return fmt.Errorf("failed to fetch bundle: %v", err)
	}

	identityKey, err := ecdh.X25519().NewPublicKey(bundle.IdentityKey)
	if err != nil {
		return fmt.Errorf("failed to parse identity key: %v", err)
	}

	signedPrekey, err := ecdh.X25519().NewPublicKey(bundle.SignedPrekey)
	if err != nil {
		return fmt.Errorf("failed to parse signed prekey: %v", err)
	}

	prekeyBundle := PrekeyBundle{
		IdentityKey:     identityKey,
		SignedPrekey:    signedPrekey,
		PrekeySignature: bundle.PrekeySignature,
	}

	if len(bundle.OneTimePrekey) > 0 {
		oneTimeKey, err := ecdh.X25519().NewPublicKey(bundle.OneTimePrekey)
		if err != nil {
			return fmt.Errorf("failed to parse one-time prekey: %v", err)
		}
		prekeyBundle.OneTimePrekey = oneTimeKey
	}

	c.user.GenerateEphemeralKey()
	initMsg, sharedSecret, err := c.user.CreateInitialMessage(prekeyBundle, nil)
	if err != nil {
		return fmt.Errorf("failed to create initial message: %v", err)
	}

	// Create Alice's ratchet state
	aliceRatchet, err := NewRatchetState()
	if err != nil {
		return fmt.Errorf("failed to create ratchet state: %v", err)
	}

	// Initialize Alice as sender - matching the working test exactly
	var sharedKey [32]byte
	copy(sharedKey[:], sharedSecret)

	// CRITICAL: Use Bob's signed prekey as his ratchet public key
	// This is what Bob will use on his side too
	aliceRatchet.ReceivingPublicKey = signedPrekey

	// Perform DH with Alice's ratchet key and Bob's signed prekey (his ratchet key)
	dhShared, err := aliceRatchet.SendingSecretKey.ECDH(aliceRatchet.ReceivingPublicKey)
	if err != nil {
		return fmt.Errorf("failed to perform DH: %v", err)
	}

	// Derive root key and sending chain key
	aliceRatchet.RootKey, aliceRatchet.ChainKeySending = kdfRootKey(sharedKey[:], dhShared)

	ad := c.user.additionalInformation(identityKey)

	c.mu.Lock()
	c.conversations[recipientID] = &Conversation{
		RemoteIdentityKey: identityKey,
		SessionID:         []byte(recipientID),
		Ratchet:           aliceRatchet,
		AdditionalData:    ad,
	}
	c.mu.Unlock()

	pbInitMsg := &pb.InitialMessage{
		IdentityKey:  initMsg.IdentityKey.Bytes(),
		EphemeralKey: initMsg.EphemeralKey.Bytes(),
	}
	if initMsg.OneTimePrekeyUsed != nil {
		pbInitMsg.OneTimePrekey = initMsg.OneTimePrekeyUsed.Bytes()
	}

	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream not initialized")
	}

	keyExchangeMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_KeyExchange{
			KeyExchange: &pb.KeyExchangeMessage{
				SenderId:       c.username,
				ReceiverId:     recipientID,
				InitialMessage: pbInitMsg,
				Timestamp:      timestamppb.Now(),
			},
		},
	}

	if err := stream.Send(keyExchangeMsg); err != nil {
		return fmt.Errorf("failed to send key exchange: %v", err)
	}

	log.Printf("initiated chat with %s", recipientID)
	return nil
}

func (c *RpcClient) handleKeyExchange(msg *pb.KeyExchangeMessage) {
	if msg.InitialMessage == nil {
		log.Printf("Key exchange message missing initial message")
		return
	}

	identityKey, err := ecdh.X25519().NewPublicKey(msg.InitialMessage.IdentityKey)
	if err != nil {
		log.Printf("failed to parse identity key: %v", err)
		return
	}

	ephemeralKey, err := ecdh.X25519().NewPublicKey(msg.InitialMessage.EphemeralKey)
	if err != nil {
		log.Printf("failed to parse ephemeral key: %v", err)
		return
	}

	initMsg := &InitialMessage{
		IdentityKey:  identityKey,
		EphemeralKey: ephemeralKey,
	}

	if len(msg.InitialMessage.OneTimePrekey) > 0 {
		oneTimeKey, err := ecdh.X25519().NewPublicKey(msg.InitialMessage.OneTimePrekey)
		if err != nil {
			log.Printf("failed to parse one-time prekey: %v", err)
			return
		}
		initMsg.OneTimePrekeyUsed = oneTimeKey
	}

	sharedSecret, err := c.user.calculateSharedSecretAsReceiver(initMsg)
	if err != nil {
		log.Printf("failed to calculate shared secret: %v", err)
		return
	}

	bobRatchet := &RatchetState{
		SendingSecretKey: c.user.SignedPrekeyPrivate,
		SendingPublicKey: c.user.SignedPrekeyPublic,
		SendingCounter:   0,
		ReceivingCounter: 0,
	}

	var sharedKey [32]byte
	copy(sharedKey[:], sharedSecret)
	bobRatchet.RootKey = sharedKey

	// CRITICAL FIX: Bob needs to know Alice's ratchet public key
	// This will be in the first message Alice sends, but we need to
	// mark that Bob hasn't received a message yet
	// The ReceivingPublicKey will be set when the first message arrives

	ad := append(identityKey.Bytes(), c.user.IdentityPublicKey.Bytes()...)
	ad = append(ad, []byte(msg.SenderId)...)

	c.mu.Lock()
	c.conversations[msg.SenderId] = &Conversation{
		RemoteIdentityKey: identityKey,
		SessionID:         []byte(msg.SenderId),
		Ratchet:           bobRatchet,
		AdditionalData:    ad,
	}
	c.mu.Unlock()

	log.Printf("key exchange completed with %s", msg.SenderId)
}

// SendHeartbeat sends a heartbeat message to keep the connection alive.
func (c *RpcClient) SendHeartbeat() error {
	c.streamMu.Lock()
	stream := c.stream
	c.streamMu.Unlock()

	if stream == nil {
		return fmt.Errorf("stream not initialized")
	}

	heartbeatMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_Heartbeat{
			Heartbeat: &pb.HeartbeatMessage{
				Timestamp: timestamppb.Now(),
			},
		},
	}

	return stream.Send(heartbeatMsg)
}

// HasConversation checks if a conversation exists with the specified user.
func (c *RpcClient) HasConversation(recipientID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.conversations[recipientID]
	return ok
}

// ListConversations returns a list of all active conversation IDs.
func (c *RpcClient) ListConversations() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	convs := make([]string, 0, len(c.conversations))
	for id := range c.conversations {
		convs = append(convs, id)
	}
	return convs
}
