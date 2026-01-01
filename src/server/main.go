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
	"github.com/zukigit/chat-gRPC/src/protos/chat"
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
	users     map[string]*auth.User
	auth.UnimplementedAuthServer
	chat.UnimplementedChatServer
}

func (s *server) register(user *auth.User) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if user != nil {
		s.users[user.GetUserName()] = user
	}
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

func (s *server) Login(ctx context.Context, requestUser *auth.User) (*auth.LoginResponse, error) {
	user, exists := s.users[requestUser.GetUserName()]
	if !exists {
		user = &auth.User{
			UserName: requestUser.UserName,
			Passwd:   requestUser.Passwd,
			IsActive: false,
		}
		s.register(user)
	}

	if user.GetPasswd() != requestUser.GetPasswd() {
		return nil, status.Errorf(codes.Unauthenticated, "invalid username or password")
	}

	token, err := s.generateToken(user.GetUserName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "could not generate token")
	}

	return &auth.LoginResponse{
		Token: token,
	}, nil
}

func (s *server) Send(ctx context.Context, req *chat.MessageRequest) (*chat.MessageRespone, error) {
	return &chat.MessageRespone{
		Success: true,
	}, nil
}

// func (s *server) HelloWorld(ctx context.Context, hello *auth.Hello) (*auth.Hello, error) {
// 	token, err := jwt.ParseWithClaims(hello.Token, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
// 		// Validate signing method
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return s.secretKey, nil
// 	})

// 	if err != nil {
// 		return nil, err
// 	}

// 	if _, ok := token.Claims.(*jwt.RegisteredClaims); !ok || !token.Valid {
// 		return nil, fmt.Errorf("invalid token claims")
// 	}

// 	return &auth.Hello{
// 		Message: "hello" + hello.Name,
// 	}, nil
// }

func main() {
	fmt.Println("starting server")

	srv := &server{
		users:     make(map[string]*auth.User),
		secretKey: []byte("no_secret"),
	}

	s := grpc.NewServer()
	auth.RegisterAuthServer(s, srv)
	chat.RegisterChatServer(s, srv)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Server listening at %v", listener.Addr())

	s.Serve(listener)
}
