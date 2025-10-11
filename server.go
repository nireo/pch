package pch

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type MessageConn struct {
	conn net.Conn
	w    *bufio.Writer
	r    *bufio.Reader
}

func (mc *MessageConn) Send(msg []byte) error {
	length := uint32(len(msg))

	binary.Write(mc.w, binary.BigEndian, length)
	mc.w.Write(msg)

	return mc.w.Flush()
}

func (mc *MessageConn) Recv() ([]byte, error) {
	var length uint32
	if err := binary.Read(mc.r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	msg := make([]byte, length)
	_, err := io.ReadFull(mc.r, msg)
	return msg, err
}

type Client struct {
	conn *MessageConn
	id   string
	send chan *Message
}

type Server struct {
	clients    map[string]*Client
	mu         sync.RWMutex
	register   chan *Client
	unregister chan *Client
	broadcast  chan *Message

	storage *Storage
}

func NewServer(dbPath string) (*Server, error) {
	storage, err := NewStorage(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	return &Server{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan *Message, 256),
		storage:    storage,
	}, nil
}

func (s *Server) Close() error {
	return s.storage.Close()
}

func (s *Server) Run() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client.id] = client
			s.mu.Unlock()
			fmt.Printf("Client registered: %s\n", client.id)

		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client.id]; ok {
				delete(s.clients, client.id)
				close(client.send)
				fmt.Printf("Client unregistered: %s\n", client.id)
			}
			s.mu.Unlock()

		case msg := <-s.broadcast:
			s.mu.RLock()
			if client, ok := s.clients[msg.ReceiverID]; ok {
				select {
				case client.send <- msg:
				default:
					close(client.send)
					delete(s.clients, client.id)
				}
			}
			s.mu.RUnlock()
		}
	}
}

func (s *Server) HandleConnection(conn net.Conn) {
	defer conn.Close()

	mc := &MessageConn{
		conn: conn,
		w:    bufio.NewWriter(conn),
		r:    bufio.NewReader(conn),
	}

	data, err := mc.Recv()
	if err != nil {
		fmt.Printf("Failed to receive initial message: %v\n", err)
		return
	}

	msg, err := DeserializeMessage(data)
	if err != nil {
		fmt.Printf("Failed to deserialize message: %v\n", err)
		return
	}

	if msg.Kind == MessageKindRegister {
		s.handleRegistration(mc, msg)
		return
	}

	if msg.Kind != MessageKindJoin {
		fmt.Printf("Expected join message, got: %v\n", msg.Kind)
		return
	}

	client := &Client{
		conn: mc,
		id:   msg.SenderID,
		send: make(chan *Message, 256),
	}

	s.register <- client

	go s.readPump(client)
	go s.writePump(client)
}

func (s *Server) handleRegistration(mc *MessageConn, msg *Message) {
	var userReg UserRegistration
	if err := gob.NewDecoder(bytes.NewBuffer(msg.Payload)).Decode(&userReg); err != nil {
		s.sendError(mc, "Invalid registration data")
		return
	}

	if !ed25519.Verify(userReg.VerifyingKey, userReg.SignedPrekey.PublicKey, userReg.SignedPrekey.Signature) {
		s.sendError(mc, "Invalid prekey signature")
		return
	}

	if s.storage.UserExists(userReg.Username) {
		s.sendError(mc, "Username already exists")
		return
	}

	userRecord := &UserRecord{
		Username:     userReg.Username,
		IdentityKey:  userReg.IdentityKey,
		VerifyingKey: userReg.VerifyingKey,
		SignedPrekey: &userReg.SignedPrekey,
		CreatedAt:    time.Now(),
	}

	if err := s.storage.StoreUser(userRecord); err != nil {
		s.sendError(mc, fmt.Sprintf("Failed to store user: %v", err))
		return
	}

	if len(userReg.OneTimePrekeys) > 0 {
		if err := s.storage.AddOTPs(userReg.Username, userReg.OneTimePrekeys); err != nil {
			s.sendError(mc, fmt.Sprintf("Failed to store OTPs: %v", err))
			return
		}
	}

	response := &Message{
		Kind:       MessageKindRegisterResponse,
		ReceiverID: userReg.Username,
		Payload:    []byte("Registration successful"),
	}

	data, _ := response.Serialize()
	mc.Send(data)

	fmt.Printf("User registered: %s (with %d OTPs)\n", userReg.Username, len(userReg.OneTimePrekeys))
}

func (s *Server) readPump(client *Client) {
	defer func() {
		s.unregister <- client
		client.conn.conn.Close()
	}()

	for {
		data, err := client.conn.Recv()
		if err != nil {
			return
		}

		msg, err := DeserializeMessage(data)
		if err != nil {
			continue
		}

		switch msg.Kind {
		case MessageKindFetchBundle:
			s.handleFetchBundle(client, msg)
		case MessageKindUploadOTPs:
			s.handleUploadOTPs(client, msg)
		case MessageKindText, MessageKindKeyExchange:
			s.broadcast <- msg
		default:
			fmt.Printf("Unknown message kind: %v\n", msg.Kind)
		}
	}
}

func (s *Server) handleFetchBundle(client *Client, msg *Message) {
	var request BundleRequest
	if err := gob.NewDecoder(bytes.NewBuffer(msg.Payload)).Decode(&request); err != nil {
		s.sendErrorToClient(client, "Invalid bundle request")
		return
	}

	userRecord, err := s.storage.GetUser(request.Username)
	if err != nil {
		s.sendErrorToClient(client, fmt.Sprintf("User not found: %s", request.Username))
		return
	}

	var otp *StoredPrekey
	otp, err = s.storage.PopOTP(request.Username)
	if err != nil {
		fmt.Printf("No OTPs available for %s\n", request.Username)
	}

	bundle := PrekeyBundleResponse{
		IdentityKey:     userRecord.IdentityKey,
		SignedPrekey:    userRecord.SignedPrekey.PublicKey,
		PrekeySignature: userRecord.SignedPrekey.Signature,
	}

	if otp != nil {
		bundle.OneTimePrekey = otp.PublicKey
		fmt.Printf("Provided OTP for %s (remaining: %d)\n", request.Username, s.mustCountOTPs(request.Username))
	}

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(bundle); err != nil {
		s.sendErrorToClient(client, "Failed to encode bundle")
		return
	}

	response := &Message{
		Kind:       MessageKindBundleResponse,
		ReceiverID: client.id,
		Payload:    buf.Bytes(),
	}

	data, _ := response.Serialize()
	client.conn.Send(data)

	fmt.Printf("Sent bundle for %s to %s\n", request.Username, client.id)
}

func (s *Server) handleUploadOTPs(client *Client, msg *Message) {
	var upload OTPUpload
	if err := gob.NewDecoder(bytes.NewBuffer(msg.Payload)).Decode(&upload); err != nil {
		s.sendErrorToClient(client, "Invalid OTP upload")
		return
	}

	if client.id != upload.Username {
		s.sendErrorToClient(client, "Cannot upload OTPs for another user")
		return
	}

	userRecord, err := s.storage.GetUser(upload.Username)
	if err != nil {
		s.sendErrorToClient(client, "User not found")
		return
	}

	for _, otp := range upload.OneTimePrekeys {
		if !ed25519.Verify(userRecord.VerifyingKey, otp.PublicKey, otp.Signature) {
			s.sendErrorToClient(client, "Invalid OTP signature")
			return
		}
	}

	if err := s.storage.AddOTPs(upload.Username, upload.OneTimePrekeys); err != nil {
		s.sendErrorToClient(client, fmt.Sprintf("Failed to store OTPs: %v", err))
		return
	}

	response := &Message{
		Kind:       MessageKindUploadOTPsResponse,
		ReceiverID: client.id,
		Payload:    []byte(fmt.Sprintf("Uploaded %d OTPs", len(upload.OneTimePrekeys))),
	}

	data, _ := response.Serialize()
	client.conn.Send(data)

	fmt.Printf("User %s uploaded %d OTPs (total: %d)\n",
		upload.Username, len(upload.OneTimePrekeys), s.mustCountOTPs(upload.Username))
}

func (s *Server) writePump(client *Client) {
	defer client.conn.conn.Close()

	for msg := range client.send {
		data, err := msg.Serialize()
		if err != nil {
			continue
		}

		if err := client.conn.Send(data); err != nil {
			return
		}
	}
}

func (s *Server) sendError(mc *MessageConn, errMsg string) {
	msg := &Message{
		Kind:    MessageKindError,
		Payload: []byte(errMsg),
	}
	data, _ := msg.Serialize()
	mc.Send(data)
	fmt.Printf("Sent error: %s\n", errMsg)
}

func (s *Server) sendErrorToClient(client *Client, errMsg string) {
	msg := &Message{
		Kind:       MessageKindError,
		ReceiverID: client.id,
		Payload:    []byte(errMsg),
	}
	select {
	case client.send <- msg:
	default:
	}
	fmt.Printf("Sent error to %s: %s\n", client.id, errMsg)
}

func (s *Server) mustCountOTPs(username string) int {
	count, _ := s.storage.CountOTPs(username)
	return count
}
