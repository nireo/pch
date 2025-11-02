package pch

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	pb "github.com/nireo/pch/pb"
	"github.com/rs/zerolog"
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
	logger        zerolog.Logger

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
	r.logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

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
			r.logger.Info().Msg("cleaning up expired auth challenges")
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

	r.logger.Info().Str("username", req.Username).Msg("registeration to username")

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
			r.logger.Err(err).Str("username", req.Username).Msg("error storing user record")
			return nil, fmt.Errorf("failed to store user %v", err)
		}
	}

	if len(req.OneTimePrekeys) > 0 {
		err := r.store.AddOTPs(req.Username, req.OneTimePrekeys)
		if err != nil {
			r.logger.Err(err).
				Str("username", req.Username).
				Msg("error storing user one-time prekeys")
			return nil, fmt.Errorf("failed to add prekeys %v", err)
		}
	}

	authChallenge, err := getAuthChallenge()
	if err != nil {
		r.logger.Err(err).Msg("failed to generate auth challenge") // this shouldn't really happen
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

	r.logger.Info().Str("username", req.Username).Msg("successful registeration")

	return res, nil
}

// FetchBundle handles requests to fetch a user's prekey bundle.
func (r *RpcServer) FetchBundle(
	ctx context.Context,
	req *pb.FetchBundleRequest,
) (*pb.FetchBundleResponse, error) {
	userRecord, err := r.store.GetUser(req.Username)
	if err != nil {
		r.logger.Err(err).Str("username", req.Username).Msg("user not found for bundle fetch")
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

	r.logger.Info().Str("username", req.Username).Msg("user prekey bundle fetched")
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
		r.logger.Err(err).Str("username", req.Username).Msg("user not found for otp upload")
		return nil, fmt.Errorf("error getting user: %v", err)
	}

	for _, otp := range req.OneTimePrekeys {
		if !ed25519.Verify(
			userRecord.VerifyingKey,
			otp.PublicKey,
			otp.Signature,
		) {
			r.logger.Error().
				Str("username", req.Username).
				Msg("invalid otp signature during upload")
			return nil, fmt.Errorf("invalid otp signature")
		}
	}

	if err := r.store.AddOTPs(req.Username, req.OneTimePrekeys); err != nil {
		r.logger.Err(err).Str("username", req.Username).Msg("error storing uploaded otps")
		return nil, fmt.Errorf("failed to store otps %v", err)
	}

	totalNow, err := r.store.CountOTPs(req.Username)
	if err != nil {
		r.logger.Err(err).Str("username", req.Username).Msg("error counting otps after upload")
		return nil, fmt.Errorf("failed to get otp key count: %v", err)
	}

	r.logger.Info().Str("username", req.Username).
		Int("uploaded", len(req.OneTimePrekeys)).
		Int("total", totalNow).
		Msg("otps uploaded successfully")

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
		r.logger.Info().Str("username", ctx.username).Msg("cleaned up stream context")
	}
}

func (r *RpcServer) handleEncryptedMessage(msg *pb.EncryptedMessage, ctx *streamContext) error {
	// TODO: if an error occurs here it leads to the issue that the conversion ratcher state is
	// incremented meaning that it should somehow be rolled back to prevent these issues.
	if !ctx.streamRegistered {
		r.logger.Error().
			Str("username", ctx.username).
			Msg("client must join before sending messages")
		return fmt.Errorf("client must join before sending messages")
	}
	receiver := msg.ReceiverId
	sender := ctx.username

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
			r.logger.Err(err).
				Str("receiver", receiver).
				Msg("failed to deliver message")
		}
	} else {
		payload, err := proto.Marshal(&pb.EncryptedMessage{
			SenderId:       sender,
			ReceiverId:     receiver,
			RatchetMessage: msg.RatchetMessage,
			Timestamp:      timestamppb.Now(),
		})
		if err != nil {
			r.logger.Err(err).Msg("failed to marshal offline message")
			return err
		}

		offlineMsg := OfflineMessage{
			Kind:      OfflineMessageEncryptedMessage,
			Content:   payload,
			Timestamp: time.Now(),
		}
		err = r.store.AddUserMessage(offlineMsg, receiver, sender)
		if err != nil {
			r.logger.Err(err).Str("receiver", receiver).
				Msg("failed to store offline message")
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
		r.logger.Error().Str("username", username).Msg("no auth challenge found for user")
		return fmt.Errorf("no auth challenge found for user")
	}
	delete(r.challenges, username)
	r.challMu.RUnlock()

	if chall.expiresAt.Before(time.Now()) {
		r.logger.Error().Str("username", username).Msg("auth challenge expired")
		return fmt.Errorf("auth challenge expired try registering again")
	}

	userRecord, err := r.store.GetUser(username)
	if err != nil {
		r.logger.Err(err).Str("username", username).Msg("user not found during join")
		return fmt.Errorf("user not found: %v", err)
	}

	if !ed25519.Verify(userRecord.VerifyingKey, chall.challenge[:], jreq.Signature) {
		r.logger.Error().Str("username", username).Msg("invalid challenge signature")
		return fmt.Errorf("invalid challenge signature")
	}

	ctx.username = username

	r.mu.Lock()
	r.activeStreams[username] = ctx.stream
	r.mu.Unlock()
	ctx.streamRegistered = true

	offlineMsgs, err := r.store.GetUserMessages(username)
	if err != nil {
		r.logger.Err(err).Str("username", username).Msg("failed to fetch offline messages")
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
		r.logger.Err(err).Str("username", username).Msg("failed to send join ack")
		return err
	}

	if len(offlineMsgs) > 0 {
		r.logger.Info().Str("username", username).Int("count", len(offlineMsgs)).
			Msg("delivered offline messages")
		if err := r.store.DeleteUserMessages(username); err != nil {
			r.logger.Err(err).Str("username", username).Msg("failed to delete offline messages")
		}
	}

	return nil
}

func (r *RpcServer) handleHeartbeatMessage(ctx *streamContext) error {
	if err := ctx.stream.Send(&pb.ServerMessage{
		MessageType: &pb.ServerMessage_Heartbeat{
			Heartbeat: &pb.HeartbeatMessage{
				Timestamp: timestamppb.Now(),
			},
		},
	}); err != nil {
		r.logger.Err(err).Str("username", ctx.username).Msg("failed to send heartbeat ack")
		return err
	}
	return nil
}

func (r *RpcServer) handleKeyExchange(msg *pb.KeyExchangeMessage, ctx *streamContext) error {
	if !ctx.streamRegistered {
		r.logger.Error().
			Str("username", ctx.username).
			Msg("client must join before key exchange")
		return fmt.Errorf("client must join before key exchange")
	}
	username := ctx.username
	receiver := msg.ReceiverId

	r.logger.Info().Str("username", username).
		Str("receiver", receiver).
		Msg("handling key exchange message")

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
			r.logger.Err(err).Str("receiver", receiver).
				Msg("failed to deliver key exchange")
		}
	} else {
		r.logger.Info().Str("username", username).
			Str("receiver", receiver).
			Msg("storing offline key exchange message")

		payload, err := proto.Marshal(&pb.KeyExchangeMessage{
			SenderId:       username,
			ReceiverId:     receiver,
			InitialMessage: msg.InitialMessage,
			Timestamp:      timestamppb.Now(),
		})
		if err != nil {
			r.logger.Info().Str("username", username).
				Str("receiver", receiver).
				Msg("failed to marshal offline key exchange message")
			return err
		}

		offlineMsg := OfflineMessage{
			Kind:      OfflineMessageKeyExchange,
			Content:   payload,
			Timestamp: time.Now(),
		}
		err = r.store.AddUserMessage(offlineMsg, receiver, username)
		if err != nil {
			r.logger.Err(err).Str("receiver", receiver).
				Msg("failed to store offline key exchange message")
			return fmt.Errorf("failed to add user message: %s", err)
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
		return r.handleHeartbeatMessage(ctx)
	case *pb.ClientMessage_KeyExchange:
		return r.handleKeyExchange(v.KeyExchange, ctx)
	default:
		r.logger.Error().Str("username", ctx.username).
			Msgf("unknown message type: %T", v)
		return fmt.Errorf("unknown message type: %T", v)
	}
}

// MessageStream handles the bidirectional streaming RPC for chat messages.
func (r *RpcServer) MessageStream(
	stream pb.ChatService_MessageStreamServer,
) error {
	r.logger.Info().Msg("stream connection initiated")

	streamCtx := &streamContext{
		streamRegistered: false,
		stream:           stream,
	}

	defer r.cleanupStreamContext(streamCtx)

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			r.logger.Info().Msgf("client closed stream normally: %s", streamCtx.username)
			return nil
		}

		if err != nil {
			r.logger.Err(err).Str("username", streamCtx.username).Msg("failed to receive message")
			return err
		}

		err = r.handleMessage(msg, streamCtx)
		if err != nil {
			r.logger.Err(err).Str("username", streamCtx.username).Msg("failed to handle message")
			return err
		}
	}
}
