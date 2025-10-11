package pch

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
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
	clients map[string]*Client
	mu      sync.RWMutex // client mutex

	register   chan *Client
	unregister chan *Client
	broadcast  chan *Message
}

func NewServer() *Server {
	return &Server{
		clients:    make(map[string]*Client),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan *Message, 256),
	}
}

func (s *Server) Run() {
	for {
		select {
		case client := <-s.register:
			s.mu.Lock()
			s.clients[client.id] = client
			s.mu.Unlock()
		case client := <-s.unregister:
			s.mu.Lock()
			if _, ok := s.clients[client.id]; ok {
				delete(s.clients, client.id)
				close(client.send)
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
		return
	}

	msg, err := DeserializeMessage(data)
	if err != nil {
		return
	}

	if msg.Kind != MessageKindJoin {
		return
	}

	// TODO: add auth challenge for them to sign a message for authentication
	client := &Client{
		conn: mc,
		id:   msg.SenderID,
		send: make(chan *Message, 256),
	}

	s.register <- client
	go s.readPump(client)
	go s.writePump(client)
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

		s.broadcast <- msg
	}
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
