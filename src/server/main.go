package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zukigit/chat-gRPC/src/protos/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	address = ":56789"
)

type server struct {
	secretKey []byte
	mu        sync.RWMutex
	userStore map[string]string
	auth.UnimplementedAuthServer
}

func (s *server) register(userName, passwd string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.userStore[userName] = passwd
}

func (s *server) generateToken(userName string) (string, error) {
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "auth",
		Subject:   userName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (s *server) Login(ctx context.Context, request *auth.LoginRequest) (*auth.LoginResponse, error) {
	passwd, exists := s.userStore[request.GetUserName()]
	if !exists {
		s.register(request.GetUserName(), request.GetPasswd())
		goto GENERATE_TOKEN
	}

	if passwd != request.GetPasswd() {
		return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
	}

GENERATE_TOKEN:
	token, err := s.generateToken(request.GetUserName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate token")
	}

	return &auth.LoginResponse{
		Token: token,
	}, nil
}

func main() {
	fmt.Println("starting server")

	srv := &server{
		userStore: make(map[string]string),
		secretKey: []byte("no_secret"),
	}

	s := grpc.NewServer()
	auth.RegisterAuthServer(s, srv)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Server listening at %v", listener.Addr())

	s.Serve(listener)
}
