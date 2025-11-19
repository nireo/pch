package pch

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"sort"
	"sync"
	"time"

	pb "github.com/nireo/pch/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const initialOtpCount = 50

// RPCClient is a gRPC client for the ChatService. It also takes care of handling encryption etc
type RPCClient struct {
	conn          *grpc.ClientConn
	srv           pb.ChatServiceClient
	user          *X3DHUser
	username      string
	conversations map[string]*Conversation
	mu            sync.RWMutex
	stream        pb.ChatService_MessageStreamClient
	streamMu      sync.Mutex
	localStore    *LocalStore

	otpPrivKeys map[[32]byte]*ecdh.PrivateKey
	otpMu       sync.RWMutex

	// a function to capture the messages for testing purposes
	onMessageReceived func(from, message string)
}

// NewRpcClient creates a new gRPC client connected to the specified address.
func NewRpcClient(addr string, username string, localStorePath string) (*RPCClient, error) {
	kacp := keepalive.ClientParameters{
		Time:                15 * time.Second,
		Timeout:             5 * time.Second,
		PermitWithoutStream: true,
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(kacp),
	)
	if err != nil {
		return nil, fmt.Errorf("error making client: %v", err)
	}

	localStore, err := NewLocalStore(localStorePath)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	var user *X3DHUser

	storedUser, err := localStore.GetX3DHState(username)
	if err == nil {
		user = storedUser
	} else if err == ErrUserNotFound {
		// the user is not found so we should generate it
		user, err = NewX3DFUser(username)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create user: %v", err)
		}

		err = user.GeneratePrekeys(false)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to generate prekeys, %v", err)
		}

		err = localStore.StoreX3DHState(user)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to store user data: %v", err)
		}
	} else {
		// real error something is wrong
		conn.Close()
		return nil, fmt.Errorf("failed to get local user: %v", err)
	}

	return &RPCClient{
		localStore:    localStore,
		conn:          conn,
		srv:           pb.NewChatServiceClient(conn),
		user:          user,
		username:      username,
		conversations: make(map[string]*Conversation),
		otpPrivKeys:   make(map[[32]byte]*ecdh.PrivateKey),
	}, nil
}

// Close closes the gRPC client connection.
func (c *RPCClient) Close() error {
	c.streamMu.Lock()
	if c.stream != nil {
		c.stream.CloseSend()
	}
	c.streamMu.Unlock()
	return c.conn.Close()
}

// generateOtps generates n one-time prekeys.
func (c *RPCClient) generateOtps(n int) ([]*pb.SignedPrekey, []*ecdh.PrivateKey, error) {
	otps := make([]*pb.SignedPrekey, n)
	privKeys := make([]*ecdh.PrivateKey, n)
	curve := ecdh.X25519()

	for i := range n {
		otpPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate otp: %w", err)
		}

		otps[i] = &pb.SignedPrekey{
			PublicKey: otpPriv.PublicKey().Bytes(),
			Signature: ed25519.Sign(
				c.user.SigningKey,
				otpPriv.PublicKey().Bytes(),
			),
			CreatedAt: timestamppb.Now(),
		}

		privKeys[i] = otpPriv
	}

	return otps, privKeys, nil
}

// Register registers the user with the server using the provided username. It generates prekeys and
// one-time prekeys as part of the registration process.
func (c *RPCClient) Register(ctx context.Context, username string) ([]byte, error) {
	signedPrekey := &pb.SignedPrekey{
		PublicKey: c.user.SignedPrekeyPublic.Bytes(),
		Signature: ed25519.Sign(
			c.user.SigningKey,
			c.user.SignedPrekeyPublic.Bytes(),
		),
		CreatedAt: timestamppb.Now(),
	}

	otps, err := c.generateAndStoreOtps(initialOtpCount)
	if err != nil {
		return nil, fmt.Errorf("failed to generate otps: %v", err)
	}

	req := &pb.RegisterRequest{
		Username:       username,
		IdentityKey:    c.user.IdentityPublicKey.Bytes(),
		VerifyingKey:   c.user.VerifyingKey,
		SignedPrekey:   signedPrekey,
		OneTimePrekeys: otps,
	}

	res, err := c.srv.Register(ctx, req)
	if err != nil {
		return nil, err
	}

	return res.AuthChallenge, nil
}

// FetchBundle fetches the prekey bundle for the specified username from the server.
func (c *RPCClient) FetchBundle(ctx context.Context, username string) (*pb.PrekeyBundle, error) {
	req := &pb.FetchBundleRequest{
		Username: username,
	}

	resp, err := c.srv.FetchBundle(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch bundle: %v", err)
	}

	return resp.Bundle, nil
}

func (c *RPCClient) generateAndStoreOtps(count int) ([]*pb.SignedPrekey, error) {
	otps, privKeys, err := c.generateOtps(count)
	if err != nil {
		return nil, fmt.Errorf("failed to generate otps: %v", err)
	}

	toStore := make(map[[32]byte][]byte, count)
	// add them to the current map
	c.otpMu.Lock()
	for i := range otps {
		var publicKeyFixed [32]byte
		copy(publicKeyFixed[:], otps[i].PublicKey)

		c.otpPrivKeys[publicKeyFixed] = privKeys[i]
		toStore[publicKeyFixed] = privKeys[i].Bytes()
	}
	c.otpMu.Unlock()

	// also add them to local storage such that they will persist even if user quits the application
	err = c.localStore.StoreOTPs(toStore)
	if err != nil {
		return nil, fmt.Errorf("error storing otps in local storage: %v", err)
	}

	return otps, nil
}

// UploadOTPs uploads one-time prekeys to the server.
func (c *RPCClient) UploadOTPs(ctx context.Context, count int) error {
	otps, err := c.generateAndStoreOtps(count)
	if err != nil {
		return err
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
func (c *RPCClient) StartChat(
	ctx context.Context,
	username string,
	authChallenge []byte,
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

	joinUsername := username
	if joinUsername == "" {
		joinUsername = c.username
	}

	jq := pb.JoinRequest{Username: joinUsername}

	if len(authChallenge) > 0 {
		sig := ed25519.Sign(c.user.SigningKey, authChallenge)
		jq.Signature = sig
		fmt.Printf("join signature: %x", sig)
	}

	log.Printf("sending join message")
	joinMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_Join{
			Join: &jq,
		},
	}

	if err := stream.Send(joinMsg); err != nil {
		return nil, fmt.Errorf("failed to send join message: %v", err)
	}

	log.Printf("receiving messages")
	go c.receiveMessages(stream)
	return stream, nil
}

// receiveMessages handles incoming messages from the stream.
func (c *RPCClient) receiveMessages(stream pb.ChatService_MessageStreamClient) {
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

func (c *RPCClient) handleOfflineMessages(messages []*pb.OfflineMessage) {
	if len(messages) == 0 {
		return
	}

	// the messages are easiest to reason with when they're sorted
	sort.Slice(messages, func(i int, j int) bool {
		return messages[i].Timestamp.AsTime().Before(messages[j].Timestamp.AsTime())
	})

	for _, msg := range messages {
		switch msg.Kind {
		case pb.OfflineMessageKind_OFFLINE_MESSAGE_KEY_EXCHANGE:
			keyExchange := &pb.KeyExchangeMessage{}
			err := proto.Unmarshal(msg.Payload, keyExchange)
			if err != nil {
				log.Printf("failed to unmarshal key exchange: %v", err)
				continue
			}

			c.handleKeyExchange(keyExchange)
		case pb.OfflineMessageKind_OFFLINE_MESSAGE_NORMAL:
			encMsg := &pb.EncryptedMessage{}
			err := proto.Unmarshal(msg.Payload, encMsg)
			if err != nil {
				log.Printf("failed to unmarshal encrypted message: %v", err)
				continue
			}

			c.handleEncryptedMessage(encMsg)
		}
	}
}

// handleServerMessage processes incoming server messages.
func (c *RPCClient) handleServerMessage(msg *pb.ServerMessage) {
	switch v := msg.MessageType.(type) {
	case *pb.ServerMessage_JoinResponse:
		c.handleOfflineMessages(v.JoinResponse.Messages)
		log.Printf("join response: %s", v.JoinResponse.Message)
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
func (c *RPCClient) handleEncryptedMessage(msg *pb.EncryptedMessage) {
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

	// after the encryption we need to plaintext mainly for performance reasons and we work under
	// the assumption that the user's computer is secure.
	err = c.localStore.StoreMessage(msg.SenderId, LocalMessage{
		Timestamp: msg.Timestamp.AsTime(),
		Content:   plaintext,
		FromLocal: false,
	})
	if err != nil {
		log.Printf("failed to store message locally: %s", err)
		return
	}

	fmt.Printf("[%s]: %s\n", msg.SenderId, plaintext)
}

// SendMessage sends an encrypted message to the specified recipient.
func (c *RPCClient) SendMessage(recipientID, text string) error {
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

	ts := timestamppb.Now()
	clientMsg := &pb.ClientMessage{
		MessageType: &pb.ClientMessage_EncryptedMessage{
			EncryptedMessage: &pb.EncryptedMessage{
				SenderId:       c.username,
				ReceiverId:     recipientID,
				RatchetMessage: pbRatchetMsg,
				Timestamp:      ts,
			},
		},
	}

	err = stream.Send(clientMsg)
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	// if the message has been successfully uploaded to the server we can then store persistantly
	// store it locally
	err = c.localStore.StoreMessage(recipientID, LocalMessage{
		FromLocal: true,
		Content:   text,
		Timestamp: ts.AsTime(),
	})
	if err != nil {
		return fmt.Errorf("failed to store message locally: %s", err)
	}

	return nil
}

func (c *RPCClient) InitiateChat(ctx context.Context, recipientID string) error {
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

	aliceRatchet, err := NewRatchetState()
	if err != nil {
		return fmt.Errorf("failed to create ratchet state: %v", err)
	}

	var sharedKey [32]byte
	copy(sharedKey[:], sharedSecret)

	aliceRatchet.ReceivingPublicKey = signedPrekey

	dhShared, err := aliceRatchet.SendingSecretKey.ECDH(aliceRatchet.ReceivingPublicKey)
	if err != nil {
		return fmt.Errorf("failed to perform DH: %v", err)
	}

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

func (c *RPCClient) handleKeyExchange(msg *pb.KeyExchangeMessage) {
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

	var sharedSecret []byte
	if len(msg.InitialMessage.OneTimePrekey) > 0 {
		var oneTimePub [32]byte
		oneTimeKey, err := ecdh.X25519().NewPublicKey(msg.InitialMessage.OneTimePrekey)
		if err != nil {
			log.Printf("failed to parse one-time prekey: %v", err)
			return
		}
		initMsg.OneTimePrekeyUsed = oneTimeKey
		copy(oneTimePub[:], oneTimeKey.Bytes())

		// this should update the user
		// TODO: can this happen at the same time causing race condition so refactor this into the
		// calculateSharedSecretAsReceiver function also this would make this function a lot cleaner
		c.otpMu.RLock()
		otpPriv, ok := c.otpPrivKeys[oneTimePub]
		if !ok {
			log.Printf(
				"failed to find one-time private key used, cannot establish shared secret properly",
			)
			c.otpMu.RUnlock()
			return
		}
		c.otpMu.RUnlock()

		c.user.OneTimePrekeyPrivate = otpPriv
		c.user.OneTimePrekeyPublic = otpPriv.PublicKey()

		sharedSecret, err = c.user.calculateSharedSecretAsReceiver(initMsg)
		if err != nil {
			log.Printf("failed to calculate shared secret: %v", err)
			return
		}

		// as the name implies these should only be used once
		c.otpMu.Lock()
		delete(c.otpPrivKeys, oneTimePub)
		c.otpMu.Unlock()

		c.user.clearOneTimePrekey()
	} else {
		sharedSecret, err = c.user.calculateSharedSecretAsReceiver(initMsg)
		if err != nil {
			log.Printf("failed to calculate shared secret: %v", err)
			return
		}
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
func (c *RPCClient) SendHeartbeat() error {
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
func (c *RPCClient) HasConversation(recipientID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.conversations[recipientID]
	return ok
}

// ListConversations returns a list of all active conversation IDs.
func (c *RPCClient) ListConversations() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	convs := make([]string, 0, len(c.conversations))
	for id := range c.conversations {
		convs = append(convs, id)
	}
	return convs
}
