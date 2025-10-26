package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nireo/pch"
)

func main() {
	username := flag.String("username", "", "username for the chat")
	serverAddr := flag.String("server", "localhost:8001", "server addr (host:port)")
	storagePath := flag.String(
		"storage",
		"",
		"path to local storage file (default: ~/.pch-chat/<username>.db)",
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "a secure end-to-end encrypted chat client.\n\n")
		fmt.Fprintf(os.Stderr, "options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *username == "" {
		fmt.Fprintln(os.Stderr, "Error: -username is required")
		flag.Usage()
		os.Exit(1)
	}

	var finalStoragePath string
	if *storagePath != "" {
		finalStoragePath = *storagePath
	} else {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("failed to get home directory: %v", err)
		}

		storageDir := filepath.Join(homeDir, ".pch-chat")
		if err := os.MkdirAll(storageDir, 0700); err != nil {
			log.Fatalf("failed to create storage directory: %v", err)
		}

		finalStoragePath = filepath.Join(storageDir, fmt.Sprintf("%s.db", *username))
	}

	client, err := pch.NewRpcClient(*serverAddr, *username, finalStoragePath)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	fmt.Printf("connected as: %s\n", *username)
	fmt.Printf("server: %s\n", *serverAddr)
	fmt.Printf("storage: %s\n\n", finalStoragePath)

	regctx := context.Background()

	fmt.Print("registering user... ")
	if err := client.Register(regctx, *username); err != nil {
		fmt.Printf("(already registered or error: %v)\n", err)
	} else {
		fmt.Println("success")
	}

	fmt.Print("connecting to chat server... ")
	if _, err := client.StartChat(context.Background(), *username); err != nil {
		log.Fatalf("failed to start chat: %v", err)
	}
	fmt.Println("connected")

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("> ")

	for scanner.Scan() {
		input := strings.TrimSpace(scanner.Text())

		if input == "" {
			fmt.Print("> ")
			continue
		}

		parts := strings.Fields(input)
		command := parts[0]

		switch command {
		case "chat":
			if len(parts) < 2 {
				fmt.Println("usage: chat <username>")
				fmt.Print("> ")
				continue
			}
			recipient := parts[1]

			if !client.HasConversation(recipient) {
				fmt.Printf("starting new chat with %s...\n", recipient)
				if err := client.InitiateChat(context.Background(), recipient); err != nil {
					fmt.Printf("failed to initiate chat: %v\n", err)
					fmt.Print("> ")
					continue
				}
				time.Sleep(200 * time.Millisecond)
				fmt.Printf("chat established with %s\n", recipient)
			} else {
				fmt.Printf("already have chat with %s\n", recipient)
			}

		case "send", "msg", "m":
			if len(parts) < 3 {
				fmt.Println("usage: send <username> <message>")
				fmt.Print("> ")
				continue
			}
			recipient := parts[1]
			message := strings.Join(parts[2:], " ")

			if !client.HasConversation(recipient) {
				fmt.Printf("no chat with %s. Use 'chat %s' first.\n", recipient, recipient)
				fmt.Print("> ")
				continue
			}

			if err := client.SendMessage(recipient, message); err != nil {
				fmt.Printf("failed to send: %v\n", err)
			} else {
				fmt.Printf("sent to %s\n", recipient)
			}

		case "list", "ls":
			convs := client.ListConversations()
			if len(convs) == 0 {
				fmt.Println("no active conversations")
			} else {
				fmt.Println("active conversations:")
				for _, c := range convs {
					fmt.Printf("- %s\n", c)
				}
			}

		case "ping", "heartbeat":
			if err := client.SendHeartbeat(); err != nil {
				fmt.Printf("failed to send heartbeat: %v\n", err)
			} else {
				fmt.Println("heartbeat sent")
			}

		case "quit", "exit", "q":
			fmt.Println("goodbye!")
			return

		default:
			fmt.Printf("unknown command: %s\n", command)
		}

		fmt.Print("> ")
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading input: %v", err)
	}
	log.Println("Client is alive. Press Ctrl+C to quit.")
	<-make(chan struct{})
}
