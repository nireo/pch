package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/nireo/pch"
)

// A minimal, print-based chat interface.
//
// Commands:
//
//	/to <user>          switch/create conversation with user
//	/conversations      list known conversations
//	/history <user>     show stored messages with user (from local store)
//	/quit               exit
//
// Regular input sends a message to the active conversation.
func main() {
	username := flag.String("username", "", "username for the chat")
	serverAddr := flag.String("server", "localhost:8001", "server addr (host:port)")
	storagePath := flag.String(
		"storage",
		"",
		"path to local storage file (default: ~/.pch-chat/<username>.db)",
	)
	flag.Parse()

	if *username == "" {
		fmt.Fprintln(os.Stderr, "Error: -username is required")
		flag.Usage()
		os.Exit(1)
	}

	storage := *storagePath
	if storage == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to get home directory: %v", err)
		}
		dir := filepath.Join(homeDir, ".pch-chat")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			log.Fatalf("failed to create storage directory: %v", err)
		}
		storage = filepath.Join(dir, fmt.Sprintf("%s.db", *username))
	}

	client, err := pch.NewRpcClient(*serverAddr, *username, storage)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	fmt.Printf("connected as: %s\nserver: %s\nstorage: %s\n\n", *username, *serverAddr, storage)

	regctx := context.Background()
	fmt.Print("registering user... ")
	authChallenge, err := client.Register(regctx, *username)
	if err != nil {
		log.Fatalf("failed to register user: %v", err)
	}
	fmt.Println("done")

	fmt.Print("connecting to chat server... ")
	if _, err := client.StartChat(context.Background(), *username, authChallenge); err != nil {
		log.Fatalf("failed to start chat: %v", err)
	}
	fmt.Println("connected")

	currentChat := ""
	conversations := make(map[string]struct{})

	client.SetOnMessageReceived(func(from, message string) {
		conversations[from] = struct{}{}
		fmt.Printf("\n%s: %s\n", from, message)
		printPrompt(currentChat)
	})

	// Prefill conversations from stored messages.
	all, err := client.LocalStore().GetAllMessages()
	if err == nil {
		for name := range all {
			conversations[name] = struct{}{}
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nbye")
		client.Close()
		os.Exit(0)
	}()

	reader := bufio.NewScanner(os.Stdin)
	printPrompt(currentChat)
	for reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if line == "" {
			printPrompt(currentChat)
			continue
		}

		if strings.HasPrefix(line, "/") {
			handleCommand(line, client, *username, conversations, &currentChat)
			printPrompt(currentChat)
			continue
		}

		if currentChat == "" {
			fmt.Println("No active conversation. Use /to <user> first.")
			printPrompt(currentChat)
			continue
		}

		ensureConversation(context.Background(), client, currentChat)

		if err := client.SendMessage(currentChat, line); err != nil {
			fmt.Printf("send error: %v\n", err)
		} else {
			fmt.Printf("%s: %s\n", *username, line)
		}
		printPrompt(currentChat)
	}

	if err := reader.Err(); err != nil {
		log.Fatalf("input error: %v", err)
	}
}

func printPrompt(currentChat string) {
	if currentChat == "" {
		fmt.Print("- to (none) > ")
		return
	}
	fmt.Printf("- to %s > ", currentChat)
}

func handleCommand(
	line string,
	client *pch.RPCClient,
	username string,
	conversations map[string]struct{},
	currentChat *string,
) {
	fields := strings.Fields(line)
	cmd := fields[0]

	switch cmd {
	case "/to":
		if len(fields) != 2 {
			fmt.Println("usage: /to <username>")
			return
		}
		target := fields[1]
		*currentChat = target
		conversations[target] = struct{}{}
		ensureConversation(context.Background(), client, target)
		fmt.Printf("switched to %s\n", target)
	case "/conversations":
		if len(conversations) == 0 {
			fmt.Println("(none)")
			return
		}
		fmt.Println("conversations:")
		for name := range conversations {
			fmt.Printf(" - %s\n", name)
		}
	case "/history":
		if len(fields) != 2 {
			fmt.Println("usage: /history <username>")
			return
		}
		target := fields[1]
		msgs, err := client.LocalStore().GetMessages(target)
		if err != nil {
			fmt.Printf("history error: %v\n", err)
			return
		}
		if len(msgs) == 0 {
			fmt.Println("(no stored messages)")
			return
		}
		for _, m := range msgs {
			sender := target
			if m.FromLocal {
				sender = username
			}
			fmt.Printf("%s: %s\n", sender, m.Content)
		}
	case "/quit", "/exit":
		fmt.Println("bye")
		client.Close()
		os.Exit(0)
	default:
		fmt.Println("commands: /to, /conversations, /history, /quit")
	}
}

func ensureConversation(ctx context.Context, client *pch.RPCClient, user string) {
	if client.HasConversation(user) {
		return
	}
	if err := client.InitiateChat(ctx, user); err != nil {
		fmt.Printf("handshake error with %s: %v\n", user, err)
	}
}
