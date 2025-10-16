package pch

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	pb "github.com/nireo/pch/pb"
)

var ErrInvalidPrekeySignature = errors.New("invalid prekey signature")

type RpcServer struct {
	pb.UnimplementedChatServiceServer
	store *Storage
}

func NewRpcServer(dbPath string) (*RpcServer, error) {
	storage, err := NewStorage(dbPath)
	if err != nil {
		return nil, err
	}

	return &RpcServer{
		store: storage,
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

	if r.store.UserExists(req.Username) {
		return nil, fmt.Errorf(
			"user already exists with username %s",
			req.Username,
		)
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
		// TODO: just use the pb keys to prevent copying and other stupid shit
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

	otp, err := r.store.PopOTP(req.Username)
	if err != nil {
		return nil, fmt.Errorf("no more otps available for user")
	}

	bundle := &pb.PrekeyBundle{
		IdentityKey:     userRecord.IdentityKey,
		SignedPrekey:    userRecord.SignedPrekey.PublicKey,
		PrekeySignature: userRecord.SignedPrekey.Signature,
	}

	if otp != nil {
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
	// TODO: authenticate the user using the keys

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
