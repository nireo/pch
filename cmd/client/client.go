package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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
		if err := os.MkdirAll(storageDir, 0o700); err != nil {
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
	authChallenge, err := client.Register(regctx, *username)
	if err != nil {
		log.Fatalf("failed to register user: %v", err)
	}
	fmt.Println("success")

	fmt.Print("connecting to chat server... ")
	if _, err := client.StartChat(context.Background(), *username, authChallenge); err != nil {
		log.Fatalf("failed to start chat: %v", err)
	}
	fmt.Println("connected")

	ui, err := pch.NewChatUI(client, *username)
	if err != nil {
		log.Fatalf("failed to initialize chat UI: %v", err)
	}
	defer ui.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		<-sigCh
		ui.Stop()
	}()

	fmt.Println("launching chat interface... (press Esc to exit)")
	if err := ui.Run(); err != nil {
		log.Fatalf("ui error: %v", err)
	}

	fmt.Println("goodbye!")
}
