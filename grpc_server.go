package pch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	pb "github.com/nireo/pch/pb"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	authChallengeExpiry          = 5 * time.Minute
	authchallengeCleanupInterval = 1 * time.Minute
)

// ErrInvalidPrekeySignature is returned when a prekey signature fails verification.
var ErrInvalidPrekeySignature = errors.New("invalid prekey signature")

// challengeEntry represents an authentication challenge for a user.
type challengeEntry struct {
	challenge [32]byte
	expiresAt time.Time
}

// RpcServer implements the gRPC server for the chat service. It manages user
// registrations, message streaming, and offline message storage.
type RpcServer struct {
	pb.UnimplementedChatServiceServer
	store         *Storage
	activeStreams map[string]pb.ChatService_MessageStreamServer // username -> stream
	mu            sync.RWMutex

	stopChallCleanup chan struct{}
	challMu          sync.RWMutex
	challenges       map[string]challengeEntry
}

// NewRpcServer creates a new instance of RpcServer with the given database path.
func NewRpcServer(dbPath string) (*RpcServer, error) {
	storage, err := NewStorage(dbPath)
	if err != nil {
		return nil, err
	}

	r := &RpcServer{
		store:            storage,
		activeStreams:    make(map[string]pb.ChatService_MessageStreamServer),
		challenges:       make(map[string]challengeEntry),
		stopChallCleanup: make(chan struct{}),
	}

	go r.cleanupAuthChallenges()
	return r, nil
}

// getAuthChallenge generates a new 32-byte authentication challenge.
func getAuthChallenge() ([32]byte, error) {
	var authChallenge [32]byte
	_, err := rand.Read(authChallenge[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to generate auth challenge: %s", err)
	}
	return authChallenge, nil
}

// cleanupAuthChallenges periodically removes expired authentication challenges.
func (r *RpcServer) cleanupAuthChallenges() {
	t := time.NewTicker(authchallengeCleanupInterval)
	defer t.Stop()

	for {
		select {
		case <-r.stopChallCleanup:
			return
		case t := <-t.C:
			r.challMu.Lock()
			for u, chall := range r.challenges {
				if chall.expiresAt.Before(t) {
					delete(r.challenges, u)
				}
			}
			r.challMu.Unlock()
		}
	}
}

// Register handles user registration requests.
func (r *RpcServer) Register(
	ctx context.Context,
	req *pb.RegisterRequest,
) (*pb.RegisterResponse, error) {
	if !ed25519.Verify(
		req.VerifyingKey,
		req.SignedPrekey.PublicKey,
		req.SignedPrekey.Signature,
	) {
		return nil, ErrInvalidPrekeySignature
	}

	// if the user already exists return an auth challenge to prove that they're the one that they
	// claim to be. They will return an signed version of this in a join message
	// TODO: create if not exists
	if !r.store.UserExists(req.Username) {
		userRecord := &UserRecord{
			Username:     req.Username,
			IdentityKey:  req.IdentityKey,
			VerifyingKey: req.VerifyingKey,
			SignedPrekey: req.SignedPrekey,
			CreatedAt:    time.Now(),
		}

		if err := r.store.StoreUser(userRecord); err != nil {
			return nil, fmt.Errorf("failed to store user %v", err)
		}
	}

	if len(req.OneTimePrekeys) > 0 {
		err := r.store.AddOTPs(req.Username, req.OneTimePrekeys)
		if err != nil {
			return nil, fmt.Errorf("failed to add prekeys %v", err)
		}
	}

	var authChallenge [32]byte
	_, err := rand.Read(authChallenge[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth challenge: %s", err)
	}

	res := &pb.RegisterResponse{
		AuthChallenge: authChallenge[:],
	}

	r.challMu.Lock()
	r.challenges[req.Username] = challengeEntry{
		challenge: authChallenge,
		expiresAt: time.Now().Add(authChallengeExpiry),
	}
	r.challMu.Unlock()

	return res, nil
}

// FetchBundle handles requests to fetch a user's prekey bundle.
func (r *RpcServer) FetchBundle(
	ctx context.Context,
	req *pb.FetchBundleRequest,
) (*pb.FetchBundleResponse, error) {
	userRecord, err := r.store.GetUser(req.Username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %s", req.Username)
	}

	bundle := &pb.PrekeyBundle{
		IdentityKey:     userRecord.IdentityKey,
		SignedPrekey:    userRecord.SignedPrekey.PublicKey,
		PrekeySignature: userRecord.SignedPrekey.Signature,
	}

	otp, err := r.store.PopOTP(req.Username)
	if err == nil && otp != nil {
		bundle.OneTimePrekey = otp.PublicKey
	}

	return &pb.FetchBundleResponse{
		Bundle: bundle,
	}, nil
}

// UploadOPTs handles requests to upload one-time prekeys.
func (r *RpcServer) UploadOPTs(
	ctx context.Context,
	req *pb.UploadOTPsRequest,
) (*pb.UploadOTPsResponse, error) {
	userRecord, err := r.store.GetUser(req.Username)
	if err != nil {
		return nil, fmt.Errorf("error getting user: %v", err)
	}

	for _, otp := range req.OneTimePrekeys {
		if !ed25519.Verify(
			userRecord.VerifyingKey,
			otp.PublicKey,
			otp.Signature,
		) {
			return nil, fmt.Errorf("invalid otp signature")
		}
	}

	if err := r.store.AddOTPs(req.Username, req.OneTimePrekeys); err != nil {
		return nil, fmt.Errorf("failed to store otps %v", err)
	}

	totalNow, err := r.store.CountOTPs(req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get otp key count: %v", err)
	}

	return &pb.UploadOTPsResponse{
		UploadedCount: int32(len(req.OneTimePrekeys)),
		TotalOtps:     int32(totalNow),
	}, nil
}

// Close shuts down the RpcServer and cleans up resources.
func (r *RpcServer) Close() error {
	r.stopChallCleanup <- struct{}{}
	return r.store.Close()
}

type streamContext struct {
	username         string
	streamRegistered bool
	stream           pb.ChatService_MessageStreamServer
}

func (r *RpcServer) cleanupStreamContext(ctx *streamContext) {
	if ctx.streamRegistered {
		r.mu.Lock()
		delete(r.activeStreams, ctx.username)
		r.mu.Unlock()
		log.Printf("stream closed for user: %s", ctx.username)
	}
}

func (r *RpcServer) handleEncryptedMessage(msg *pb.EncryptedMessage, ctx *streamContext) error {
	// TODO: if an error occurs here it leads to the issue that the conversion ratcher state is
	// incremented meaning that it should somehow be rolled back to prevent these issues.
	if !ctx.streamRegistered {
		return fmt.Errorf("client must join before sending messages")
	}
	receiver := msg.ReceiverId
	sender := ctx.username

	log.Printf("message from %s to %s", sender, receiver)

	r.mu.RLock()
	recipientStream, ok := r.activeStreams[receiver]
	r.mu.RUnlock()

	if ok {
		err := recipientStream.Send(&pb.ServerMessage{
			MessageType: &pb.ServerMessage_EncryptedMessage{
				EncryptedMessage: &pb.EncryptedMessage{
					SenderId:       sender,
					ReceiverId:     receiver,
					RatchetMessage: msg.RatchetMessage,
					Timestamp:      timestamppb.Now(),
				},
			},
		})
		if err != nil {
			log.Printf("failed to deliver message to %s: %v", receiver, err)
		}
	} else {
		log.Printf("recipient %s offline, ", receiver)
		payload, err := proto.Marshal(&pb.EncryptedMessage{
			SenderId:       sender,
			ReceiverId:     receiver,
			RatchetMessage: msg.RatchetMessage,
			Timestamp:      timestamppb.Now(),
		})
		if err != nil {
			log.Printf("failed to marshal message: %v", err)
			return err
		}

		offlineMsg := OfflineMessage{
			Kind:      OfflineMessageEncryptedMessage,
			Content:   payload,
			Timestamp: time.Now(),
		}
		err = r.store.AddUserMessage(offlineMsg, receiver, sender)
		if err != nil {
			log.Printf("failed to add user message: %v", err)
			return fmt.Errorf("failed to add user message: %s", err)
		}
	}

	return nil
}

func (r *RpcServer) handleJoinMessage(jreq *pb.JoinRequest, ctx *streamContext) error {
	username := jreq.Username
	r.challMu.RLock()
	chall, ok := r.challenges[username]
	if !ok {
		r.challMu.Unlock()
		return fmt.Errorf("no auth challenge found for user")
	}
	delete(r.challenges, username)
	r.challMu.RUnlock()

	if chall.expiresAt.Before(time.Now()) {
		return fmt.Errorf("auth challenge expired try registering again")
	}

	userRecord, err := r.store.GetUser(username)
	if err != nil {
		return fmt.Errorf("user not found: %v", err)
	}

	if !ed25519.Verify(userRecord.VerifyingKey, chall.challenge[:], jreq.Signature) {
		return fmt.Errorf("invalid challenge signature")
	}

	ctx.username = username

	r.mu.Lock()
	r.activeStreams[username] = ctx.stream
	r.mu.Unlock()
	ctx.streamRegistered = true

	log.Printf("client joined: %s", username)

	offlineMsgs, err := r.store.GetUserMessages(username)
	if err != nil {
		log.Printf("failed to offline messages: %s", err)
		offlineMsgs = nil
	}

	pbOffline := make([]*pb.OfflineMessage, 0, len(offlineMsgs))
	for _, msg := range offlineMsgs {
		var kind pb.OfflineMessageKind
		switch msg.Kind {
		case OfflineMessageEncryptedMessage:
			kind = pb.OfflineMessageKind_OFFLINE_MESSAGE_NORMAL
		case OfflineMessageKeyExchange:
			kind = pb.OfflineMessageKind_OFFLINE_MESSAGE_KEY_EXCHANGE
		}

		pbOffline = append(pbOffline, &pb.OfflineMessage{
			Payload:   msg.Content,
			Timestamp: timestamppb.New(msg.Timestamp),
			Kind:      kind,
		})
	}

	if err := ctx.stream.Send(&pb.ServerMessage{
		MessageType: &pb.ServerMessage_JoinResponse{
			JoinResponse: &pb.JoinResponse{
				Timestamp: timestamppb.Now(),
				Message:   "successfully joined",
				Messages:  pbOffline,
			},
		},
	}); err != nil {
		log.Printf("failed to send join ack: %v", err)
	}

	if len(offlineMsgs) > 0 {
		log.Printf("delivered %d offline messages to %s", len(offlineMsgs), username)
		if err := r.store.DeleteUserMessages(username); err != nil {
			log.Printf("failed to delete offline messages: %v", err)
		}
	}

	return nil
}

func (r *RpcServer) handleHeartbeatMessage(msg *pb.HeartbeatMessage, ctx *streamContext) error {
	if err := ctx.stream.Send(&pb.ServerMessage{
		MessageType: &pb.ServerMessage_Heartbeat{
			Heartbeat: &pb.HeartbeatMessage{
				Timestamp: timestamppb.Now(),
			},
		},
	}); err != nil {
		log.Printf("failed to send heartbeat ack: %v", err)
		return err
	}
	return nil
}

func (r *RpcServer) handleKeyExchange(msg *pb.KeyExchangeMessage, ctx *streamContext) error {
	if !ctx.streamRegistered {
		return fmt.Errorf("client must join before key exchange")
	}
	username := ctx.username
	receiver := msg.ReceiverId

	log.Printf("key exchange from %s to %s", username, receiver)

	r.mu.RLock()
	recipientStream, ok := r.activeStreams[receiver]
	r.mu.RUnlock()

	if ok {
		err := recipientStream.Send(&pb.ServerMessage{
			MessageType: &pb.ServerMessage_KeyExchange{
				KeyExchange: &pb.KeyExchangeMessage{
					SenderId:       username,
					ReceiverId:     receiver,
					InitialMessage: msg.InitialMessage,
				},
			},
		})
		if err != nil {
			log.Printf("failed to deliver key exchange to %s: %v", receiver, err)
		}
	} else {
		log.Printf("recipient %s offline for key exchange", receiver)

		payload, err := proto.Marshal(&pb.KeyExchangeMessage{
			SenderId:       username,
			ReceiverId:     receiver,
			InitialMessage: msg.InitialMessage,
			Timestamp:      timestamppb.Now(),
		})
		if err != nil {
			log.Printf("failed to marshal key exchange: %v", err)
			return err
		}

		offlineMsg := OfflineMessage{
			Kind:      OfflineMessageKeyExchange,
			Content:   payload,
			Timestamp: time.Now(),
		}
		err = r.store.AddUserMessage(offlineMsg, receiver, username)
		if err != nil {
			log.Printf("failed to store offline key exchange: %v", err)
		}
	}

	return nil
}

func (r *RpcServer) handleMessage(msg *pb.ClientMessage, ctx *streamContext) error {
	switch v := msg.MessageType.(type) {
	case *pb.ClientMessage_Join:
		return r.handleJoinMessage(v.Join, ctx)
	case *pb.ClientMessage_EncryptedMessage:
		return r.handleEncryptedMessage(v.EncryptedMessage, ctx)
	case *pb.ClientMessage_Heartbeat:
		return r.handleHeartbeatMessage(v.Heartbeat, ctx)
	case *pb.ClientMessage_KeyExchange:
		return r.handleKeyExchange(v.KeyExchange, ctx)
	default:
		log.Printf("unknown message type from %s: %T", ctx.username, v)
		return fmt.Errorf("unknown message type: %T", v)
	}
}

// MessageStream handles the bidirectional streaming RPC for chat messages.
func (r *RpcServer) MessageStream(
	stream pb.ChatService_MessageStreamServer,
) error {
	log.Println("stream connection initiated")

	streamCtx := &streamContext{
		streamRegistered: false,
		stream:           stream,
	}

	defer r.cleanupStreamContext(streamCtx)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("client closed stream normally: %s", streamCtx.username)
			return nil
		}

		if err != nil {
			log.Printf("stream error for user %s: %v", streamCtx.username, err)
			return err
		}

		err = r.handleMessage(msg, streamCtx)
		if err != nil {
			log.Printf("failed to handle message for user %s: %v", streamCtx.username, err)
			return err
		}
	}
}
