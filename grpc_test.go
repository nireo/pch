package pch

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"net"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	pb "github.com/nireo/pch/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024 * 14

func TestMessageSendReceive(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	server, err := NewRpcServer("file.db")
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()
	defer func() {
		os.Remove("file.db")
	}()

	pb.RegisterChatServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()
	defer s.Stop()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	alice, err := createTestClient(t, ctx, bufDialer, "alice")
	if err != nil {
		t.Fatalf("Failed to create alice: %v", err)
	}
	defer alice.Close()

	bob, err := createTestClient(t, ctx, bufDialer, "bob")
	if err != nil {
		t.Fatalf("Failed to create bob: %v", err)
	}
	defer bob.Close()

	if err := alice.Register(ctx, "alice"); err != nil {
		t.Fatalf("Failed to register alice: %v", err)
	}

	if err := bob.Register(ctx, "bob"); err != nil {
		t.Fatalf("Failed to register bob: %v", err)
	}

	if _, err := alice.StartChat(ctx, "alice"); err != nil {
		t.Fatalf("Failed to start alice's stream: %v", err)
	}

	if _, err := bob.StartChat(ctx, "bob"); err != nil {
		t.Fatalf("Failed to start bob's stream: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	if err := alice.InitiateChat(ctx, "bob"); err != nil {
		t.Fatalf("Failed to initiate chat: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	if !alice.HasConversation("bob") {
		t.Fatal("Alice should have conversation with bob")
	}

	if !bob.HasConversation("alice") {
		t.Fatal("Bob should have conversation with alice")
	}

	// Setup message receiver for Bob
	var receivedMsg string
	var receivedFrom string
	var wg sync.WaitGroup
	wg.Add(1)

	bob.onMessageReceived = func(from, message string) {
		receivedFrom = from
		receivedMsg = message
		wg.Done()
	}

	// Alice sends message to Bob
	testMessage := "Hello Bob, this is a secret message!"
	if err := alice.SendMessage("bob", testMessage); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for message to be received")
	}

	if receivedMsg != testMessage {
		t.Fatalf("got wrong message: %s", receivedMsg)
	}

	if receivedFrom != "alice" {
		t.Errorf("Expected message from alice, got %s", receivedFrom)
	}

	if err := bob.SendMessage("alice", "Hi Alice, message received!"); err != nil {
		t.Fatalf("Failed to send reply: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	aliceConvs := alice.ListConversations()
	if len(aliceConvs) != 1 || aliceConvs[0] != "bob" {
		t.Errorf("Expected alice to have 1 conversation with bob, got %v", aliceConvs)
	}

	bobConvs := bob.ListConversations()
	if len(bobConvs) != 1 || bobConvs[0] != "alice" {
		t.Errorf("Expected bob to have 1 conversation with alice, got %v", bobConvs)
	}
}

func createTestClient(
	t *testing.T,
	ctx context.Context,
	dialer func(context.Context, string) (net.Conn, error),
	username string,
) (*RpcClient, error) {
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection: %v", err)
	}

	user, err := NewX3DFUser(username)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	localPath := path.Join(t.TempDir(), "localstore.db")
	ls, err := NewLocalStore(localPath)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to store local store: %v", err)
	}

	return &RpcClient{
		conn:          conn,
		srv:           pb.NewChatServiceClient(conn),
		user:          user,
		username:      username,
		conversations: make(map[string]*Conversation),
		otpPrivKeys:   make(map[[32]byte]*ecdh.PrivateKey),
		localStore:    ls,
	}, nil
}

func TestMultipleMessages(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	tpath := path.Join(t.TempDir(), "server.db")

	server, err := NewRpcServer(tpath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	pb.RegisterChatServiceServer(s, server)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited: %v", err)
		}
	}()
	defer s.Stop()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	ctx := context.Background()

	alice, _ := createTestClient(t, ctx, bufDialer, "alice")
	defer alice.Close()
	bob, _ := createTestClient(t, ctx, bufDialer, "bob")
	defer bob.Close()

	alice.Register(ctx, "alice")
	bob.Register(ctx, "bob")
	alice.StartChat(ctx, "alice")
	bob.StartChat(ctx, "bob")

	time.Sleep(100 * time.Millisecond)

	alice.InitiateChat(ctx, "bob")
	time.Sleep(500 * time.Millisecond)

	var wg sync.WaitGroup
	var recordedMessages []string
	bob.onMessageReceived = func(from, plaintext string) {
		recordedMessages = append(recordedMessages, plaintext)
		wg.Done()
	}

	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
		"Message 4",
		"Message 5",
	}

	for _, msg := range messages {
		wg.Add(1)
		if err := alice.SendMessage("bob", msg); err != nil {
			t.Errorf("Failed to send message '%s': %v", msg, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()

	alice.mu.RLock()
	aliceConv := alice.conversations["bob"]
	alice.mu.RUnlock()

	if aliceConv.Ratchet.SendingCounter < uint64(len(messages)) {
		t.Errorf("Expected sending counter >= %d, got %d",
			len(messages), aliceConv.Ratchet.SendingCounter)
	}

	for i := range messages {
		if messages[i] != recordedMessages[i] {
			t.Fatalf("unexpected message: %s", recordedMessages[i])
		}
	}
}

func TestMessageWithoutKeyExchange(t *testing.T) {
	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()

	tpath := path.Join(t.TempDir(), "server.db")
	server, err := NewRpcServer(tpath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	pb.RegisterChatServiceServer(s, server)

	go func() {
		s.Serve(lis)
	}()
	defer s.Stop()

	bufDialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	ctx := context.Background()

	alice, _ := createTestClient(t, ctx, bufDialer, "alice")
	defer alice.Close()

	alice.Register(ctx, "alice")
	alice.StartChat(ctx, "alice")

	err = alice.SendMessage("bob", "This should fail")
	if err == nil {
		t.Error("Expected error when sending without key exchange")
	}

	expectedErr := "no conversation with bob"
	if err.Error() != expectedErr {
		t.Errorf("Expected error '%s', got '%s'", expectedErr, err.Error())
	}
}
