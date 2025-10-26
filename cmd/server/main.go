package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nireo/pch"
	pb "github.com/nireo/pch/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

func main() {
	var (
		port   = flag.String("port", "8001", "Server port")
		dbPath = flag.String("db", "./pch.db", "Database file path")
		debug  = flag.Bool("debug", false, "Enable debug mode with reflection")
	)
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("starting pch server on port %s with database %s", *port, *dbPath)

	rpcServer, err := pch.NewRpcServer(*dbPath)
	if err != nil {
		log.Fatalf("failed to create RPC server: %v", err)
	}
	defer func() {
		if err := rpcServer.Close(); err != nil {
			log.Printf("error closing RPC server: %v", err)
		}
	}()

	keepaliveParams := keepalive.ServerParameters{
		Time:    30 * time.Second,
		Timeout: 10 * time.Second,
	}

	keepaliveEnforcement := keepalive.EnforcementPolicy{
		MinTime:             5 * time.Second,
		PermitWithoutStream: true,
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepaliveParams),
		grpc.KeepaliveEnforcementPolicy(keepaliveEnforcement),
		grpc.MaxRecvMsgSize(10 * 1024 * 1024), // 10mb max
		grpc.MaxSendMsgSize(10 * 1024 * 1024),
	}

	grpcServer := grpc.NewServer(opts...)

	pb.RegisterChatServiceServer(grpcServer, rpcServer)

	if *debug {
		reflection.Register(grpcServer)
		log.Println("grpc reflection enabled (debug mode)")
	}

	listener, err := net.Listen("tcp", ":"+*port)
	if err != nil {
		log.Fatalf("failed to listen on port %s: %v", *port, err)
	}

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-shutdownChan
		log.Println("shutting down...")
		grpcServer.GracefulStop()
	}()

	log.Printf("pch server listening on :%s", *port)
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
