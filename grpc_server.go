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

var ErrInvalidPrekeySignature = errors.New("invalid prekey signature")

type RpcServer struct {
	pb.UnimplementedChatServiceServer
	store         *Storage
	activeStreams map[string]pb.ChatService_MessageStreamServer // username -> stream
	mu            sync.RWMutex

	challMu    sync.RWMutex
	challenges map[string][32]byte
}

func NewRpcServer(dbPath string) (*RpcServer, error) {
	storage, err := NewStorage(dbPath)
	if err != nil {
		return nil, err
	}

	return &RpcServer{
		store:         storage,
		activeStreams: make(map[string]pb.ChatService_MessageStreamServer),
	}, nil
}

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
	if r.store.UserExists(req.Username) {
		var authChallenge [32]byte
		_, err := rand.Read(authChallenge[:])
		if err != nil {
			return nil, fmt.Errorf("failed to generate auth challenge: %s", err)
		}

		res := &pb.RegisterResponse{
			AuthChallenge: authChallenge[:],
		}

		r.challMu.Lock()
		r.challenges[req.Username] = authChallenge
		r.challMu.Unlock()

		return res, nil
	}

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

	if len(req.OneTimePrekeys) > 0 {
		err := r.store.AddOTPs(req.Username, req.OneTimePrekeys)
		if err != nil {
			return nil, fmt.Errorf("failed to add prekeys %v", err)
		}
	}

	return &pb.RegisterResponse{}, nil
}

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

func (r *RpcServer) Close() error {
	return r.store.Close()
}

// MessageStream handles the bidirectional streaming RPC for chat messages.
func (r *RpcServer) MessageStream(
	stream pb.ChatService_MessageStreamServer,
) error {
	var username string
	var streamRegistered bool

	log.Println("stream connection initiated")

	defer func() {
		if streamRegistered {
			r.mu.Lock()
			delete(r.activeStreams, username)
			r.mu.Unlock()
			log.Printf("stream closed for user: %s", username)
		}
	}()

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Printf("client closed stream normally: %s", username)
			return nil
		}

		if err != nil {
			log.Printf("stream error for user %s: %v", username, err)
			return err
		}

		switch v := msg.MessageType.(type) {
		case *pb.ClientMessage_Join:
			username = v.Join.Username

			r.mu.Lock()
			r.activeStreams[username] = stream
			r.mu.Unlock()
			streamRegistered = true

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

			if err := stream.Send(&pb.ServerMessage{
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

		case *pb.ClientMessage_EncryptedMessage:
			if !streamRegistered {
				return fmt.Errorf("client must join before sending messages")
			}

			log.Printf("message from %s to %s", username, v.EncryptedMessage.ReceiverId)

			r.mu.RLock()
			recipientStream, ok := r.activeStreams[v.EncryptedMessage.ReceiverId]
			r.mu.RUnlock()

			if ok {
				err := recipientStream.Send(&pb.ServerMessage{
					MessageType: &pb.ServerMessage_EncryptedMessage{
						EncryptedMessage: &pb.EncryptedMessage{
							SenderId:       username,
							ReceiverId:     v.EncryptedMessage.ReceiverId,
							RatchetMessage: v.EncryptedMessage.RatchetMessage,
							Timestamp:      timestamppb.Now(),
						},
					},
				})
				if err != nil {
					log.Printf("Failed to deliver message to %s: %v",
						v.EncryptedMessage.ReceiverId, err)
				}
			} else {
				log.Printf("Recipient %s offline, ", v.EncryptedMessage.ReceiverId)
				payload, err := proto.Marshal(&pb.EncryptedMessage{
					SenderId:       username,
					ReceiverId:     v.EncryptedMessage.ReceiverId,
					RatchetMessage: v.EncryptedMessage.RatchetMessage,
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
				err = r.store.AddUserMessage(offlineMsg, v.EncryptedMessage.ReceiverId, username)
				if err != nil {
					log.Printf("failed to add user message: %v", err)
				}
			}

		case *pb.ClientMessage_KeyExchange:
			if !streamRegistered {
				return fmt.Errorf("client must join before key exchange")
			}

			log.Printf("key exchange from %s to %s", username, v.KeyExchange.ReceiverId)

			r.mu.RLock()
			recipientStream, ok := r.activeStreams[v.KeyExchange.ReceiverId]
			r.mu.RUnlock()

			if ok {
				err := recipientStream.Send(&pb.ServerMessage{
					MessageType: &pb.ServerMessage_KeyExchange{
						KeyExchange: &pb.KeyExchangeMessage{
							SenderId:       username,
							ReceiverId:     v.KeyExchange.ReceiverId,
							InitialMessage: v.KeyExchange.InitialMessage,
						},
					},
				})
				if err != nil {
					log.Printf("failed to deliver key exchange to %s: %v",
						v.KeyExchange.ReceiverId, err)
				}
			} else {
				log.Printf("recipient %s offline for key exchange",
					v.KeyExchange.ReceiverId)

				payload, err := proto.Marshal(&pb.KeyExchangeMessage{
					SenderId:       username,
					ReceiverId:     v.KeyExchange.ReceiverId,
					InitialMessage: v.KeyExchange.InitialMessage,
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
				err = r.store.AddUserMessage(offlineMsg, v.KeyExchange.ReceiverId, username)
				if err != nil {
					log.Printf("failed to store offline key exchange: %v", err)
				}
			}

		case *pb.ClientMessage_Heartbeat:
			if err := stream.Send(&pb.ServerMessage{
				MessageType: &pb.ServerMessage_Heartbeat{
					Heartbeat: &pb.HeartbeatMessage{
						Timestamp: timestamppb.Now(),
					},
				},
			}); err != nil {
				log.Printf("failed to send heartbeat ack: %v", err)
				return err
			}

		default:
			log.Printf("unknown message type from %s: %T", username, v)
			return fmt.Errorf("unknown message type: %T", v)
		}
	}
}
