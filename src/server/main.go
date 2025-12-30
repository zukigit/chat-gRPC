package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"google.golang.org/grpc"
)

const (
	address = ":56789"
)

type server struct {
	auth.UnimplementedAuthServer
}

func (s *server) Login(ctx context.Context, request *auth.LoginRequest) (*auth.LoginResponse, error) {
	fmt.Println("username", request.GetUserName())
	fmt.Println("passwd", request.GetPasswd())

	return &auth.LoginResponse{
		Token: "123123",
	}, nil
}

func main() {
	fmt.Println("starting server")

	srv := &server{}

	s := grpc.NewServer()
	auth.RegisterAuthServer(s, srv)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Server listening at %v", listener.Addr())

	s.Serve(listener)
}
